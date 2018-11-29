public enum BCryptError: String, Error {
    case invalidSaltByteCount
}

extension BCryptError {
    public var reason: String {
        switch self {
            case .invalidSaltByteCount:
                return "BCrypt salt requires 16 bytes"
        }
    }
}