# BCrypt
![Swift](http://img.shields.io/badge/swift-4.2-brightgreen.svg)

## Usage

### Hash
```swift
import BCrypt

let bytes = try BCrypt.hash(message: "test")
print(bytes.string())
```

### Hash with salt
```swift
import BCrypt

let salt = Salt(cost: 14)
let bytes = try BCrypt.hash(message: "test", with: salt)
print(bytes.string())
```

### Compare
```swift
import BCrypt

let bytes = try BCrypt.hash(message: "test")
let result = try BCrypt.compare(message: "test", against: bytes)
print(result) // => True
```