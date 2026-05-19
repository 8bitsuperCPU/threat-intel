import Foundation
import CryptoKit

enum HashUtil {
    /// SHA256 hash of a string — used for content deduplication.
    static func sha256(_ input: String) -> String {
        guard let data = input.data(using: .utf8) else { return "" }
        return SHA256.hash(data: data).compactMap { String(format: "%02x", $0) }.joined()
    }

    /// Canonicalize a URL for deduplication (lowercase scheme+host, sort query params, strip fragments).
    static func canonicalizeURL(_ urlString: String) -> String? {
        guard var components = URLComponents(string: urlString.trimmingCharacters(in: .whitespaces)) else {
            return nil
        }
        components.scheme = components.scheme?.lowercased()
        components.host = components.host?.lowercased()
        components.fragment = nil
        components.queryItems = components.queryItems?.sorted { ($0.name, $0.value ?? "") < ($1.name, $1.value ?? "") }
        return components.string
    }
}
