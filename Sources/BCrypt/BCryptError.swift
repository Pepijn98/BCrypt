public enum BCryptError: String, Error {
    case invalidHash
    case invalidSaltByteCount
    case invalidSaltCost
}

import Debugging

extension BCryptError: Debuggable {
    public var reason: String {
        switch self {
        case .invalidHash:
            return "The hash being parsed does not match the recognized format"
        case .invalidSaltByteCount:
            return "BCrypt salt requires 16 bytes"
        case .invalidSaltCost:
            return "Invalid salt cost format"
        }
    }

    public var identifier: String {
        return rawValue
    }

    public var possibleCauses: [String] {
        return []
    }

    public var suggestedFixes: [String] {
        return []
    }
}