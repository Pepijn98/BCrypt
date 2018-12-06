# BCrypt
![Swift](http://img.shields.io/badge/swift-4.2-brightgreen.svg)

## Usage

### Hash
```swift
import BCrypt

let bytes = try BCrypt.hash(message: "test")
print(String(bytes: bytes, encoding: .utf8) ?? "")
```

### Hash with salt
```swift
import BCrypt

let salt = Salt(cost: 14)
let bytes = try BCrypt.hash(message: "test", with: salt)
print(String(bytes: bytes, encoding: .utf8) ?? "")
```

### Compare
```swift
import BCrypt

let bytes = try BCrypt.hash(message: "test")
let result = try BCrypt.compare(message: "test", with: bytes)
print(result) // => True
```