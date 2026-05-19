import Foundation

/// Centralized HTTP client with retry, backoff, and ETag/Last-Modified support.
final class APIClient: Sendable {
    private let session: URLSession
    private let userAgent = "ThreatIntel/1.0 (macOS; Swift)"

    init() {
        let config = URLSessionConfiguration.default
        config.timeoutIntervalForRequest = 30
        config.timeoutIntervalForResource = 120
        config.waitsForConnectivity = true
        self.session = URLSession(configuration: config)
    }

    /// Perform a GET request with conditional headers and exponential backoff.
    /// Returns (data, isModified). isModified=false means 304 Not Modified.
    func fetch(
        url: URL,
        headers: [String: String] = [:],
        etag: String? = nil,
        lastModified: String? = nil,
        maxRetries: Int = 3
    ) async throws -> (Data, Bool) {
        var attempt = 0
        var lastError: Error?

        while attempt <= maxRetries {
            do {
                var request = URLRequest(url: url)
                request.httpMethod = "GET"
                request.setValue(userAgent, forHTTPHeaderField: "User-Agent")

                for (key, value) in headers {
                    request.setValue(value, forHTTPHeaderField: key)
                }
                if let etag = etag {
                    request.setValue(etag, forHTTPHeaderField: "If-None-Match")
                }
                if let lastModified = lastModified {
                    request.setValue(lastModified, forHTTPHeaderField: "If-Modified-Since")
                }

                let (data, response) = try await session.data(for: request)

                guard let httpResponse = response as? HTTPURLResponse else {
                    throw APIClientError.invalidResponse
                }

                if httpResponse.statusCode == 304 {
                    return (Data(), false) // Not modified
                }

                guard (200...299).contains(httpResponse.statusCode) else {
                    throw APIClientError.httpError(statusCode: httpResponse.statusCode, body: String(data: data, encoding: .utf8) ?? "")
                }

                return (data, true)

            } catch {
                lastError = error
                attempt += 1
                if attempt <= maxRetries {
                    let delay = pow(2.0, Double(attempt)) // 2, 4, 8 seconds
                    try? await Task.sleep(nanoseconds: UInt64(delay * 1_000_000_000))
                }
            }
        }

        throw lastError ?? APIClientError.unknown
    }
}

enum APIClientError: LocalizedError {
    case invalidResponse
    case httpError(statusCode: Int, body: String)
    case unknown

    var errorDescription: String? {
        switch self {
        case .invalidResponse: return "Invalid HTTP response"
        case .httpError(let code, let body): return "HTTP \(code): \(body.prefix(200))"
        case .unknown: return "Unknown API error"
        }
    }
}
