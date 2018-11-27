public enum BCryptError: String, Error {
    case invalidSaltByteCount
    case invalidSaltCost
}

extension BCryptError {
    public var reason: String {
        switch self {
            case .invalidSaltByteCount:
                return "BCrypt salt requires 16 bytes"
            case .invalidSaltCost:
                return "Invalid salt cost format"
        }
    }
}