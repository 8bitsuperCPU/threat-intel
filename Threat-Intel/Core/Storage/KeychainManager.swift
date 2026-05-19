import Foundation
import Security

/// macOS Keychain wrapper for storing API keys per source.
final class KeychainManager: KeychainProtocol, Sendable {
    static let shared = KeychainManager()
    private let serviceName = "com.threatintel.apikeys"

    private init() {}

    func save(key: String, value: String) throws {
        guard let data = value.data(using: .utf8) else {
            throw KeychainError.encodingFailed
        }

        // Delete existing if present
        try? delete(key: key)

        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: key,
            kSecValueData: data,
            kSecAttrAccessible: kSecAttrAccessibleAfterFirstUnlock,
        ]

        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status: Int(status))
        }
    }

    func read(key: String) throws -> String? {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: key,
            kSecReturnData: true,
            kSecMatchLimit: kSecMatchLimitOne,
        ]

        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)

        guard status == errSecSuccess, let data = result as? Data else {
            if status == errSecItemNotFound { return nil }
            throw KeychainError.readFailed(status: Int(status))
        }

        return String(data: data, encoding: .utf8)
    }

    func delete(key: String) throws {
        let query: [CFString: Any] = [
            kSecClass: kSecClassGenericPassword,
            kSecAttrService: serviceName,
            kSecAttrAccount: key,
        ]
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status: Int(status))
        }
    }
}

enum KeychainError: LocalizedError {
    case encodingFailed
    case saveFailed(status: Int)
    case readFailed(status: Int)
    case deleteFailed(status: Int)

    var errorDescription: String? {
        switch self {
        case .encodingFailed: return "Failed to encode keychain data"
        case .saveFailed(let s): return "Keychain save failed (status: \(s))"
        case .readFailed(let s): return "Keychain read failed (status: \(s))"
        case .deleteFailed(let s): return "Keychain delete failed (status: \(s))"
        }
    }
}
