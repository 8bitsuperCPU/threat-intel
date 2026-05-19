import Foundation

/// Token-bucket rate limiter for API calls.
/// Each source gets its own limiter instance.
actor RateLimiter {
    private let maxRequestsPerMinute: Int
    private var tokens: Double
    private var lastRefill: Date

    init(maxRequestsPerMinute: Int) {
        self.maxRequestsPerMinute = maxRequestsPerMinute
        self.tokens = Double(maxRequestsPerMinute)
        self.lastRefill = Date()
    }

    /// Wait until a token is available, then consume it.
    func acquire() async {
        refill()
        while tokens < 1.0 {
            let waitTime = (1.0 - tokens) * (60.0 / Double(maxRequestsPerMinute))
            try? await Task.sleep(nanoseconds: UInt64(waitTime * 1_000_000_000))
            refill()
        }
        tokens -= 1.0
    }

    private func refill() {
        let now = Date()
        let elapsed = now.timeIntervalSince(lastRefill)
        let refillAmount = elapsed * (Double(maxRequestsPerMinute) / 60.0)
        tokens = min(Double(maxRequestsPerMinute), tokens + refillAmount)
        lastRefill = now
    }
}
