# Fortress Crypt iOS — Build Instructions

## Prerequisites
- Xcode 15.0+
- iOS 17.0+ deployment target
- macOS Sonoma 14.0+ (for development)
- CocoaPods or Swift Package Manager

## Step 1: Create Xcode Project
1. Open Xcode → File → New → Project → App
2. Product Name: **FortressCrypt**
3. Interface: **SwiftUI**
4. Language: **Swift**
5. Bundle ID: `com.yourname.fortresscrypt`

## Step 2: Add Dependencies via SPM
In Xcode: File → Add Package Dependencies, then add:

| Package | URL | Purpose |
|---------|-----|---------|
| OpenSSL | `https://github.com/nicklama/swift-openssl` | Camellia-256, scrypt, SHA3 |
| Swift Argon2 | `https://github.com/nicklama/swift-argon2` | Argon2id KDF |

**Note on packages:** The exact SPM URLs above may need updating. Search the Swift Package Index (https://swiftpackageindex.com) for the latest OpenSSL and Argon2 iOS packages. Alternatives:
- OpenSSL: `krzyzanowskim/OpenSSL` (CocoaPod) or `nicklama/swift-openssl`
- Argon2: `nicklama/swift-argon2` or `tmthecoder/Argon2Swift`
- For ML-KEM (optional): `nicklama/liboqs-swift` or compile `liboqs` C library manually

## Step 3: Add Source Files
Copy all `.swift` files from this project into your Xcode project, maintaining the folder structure:
```
FortressCrypt/
  Crypto/           ← Encryption engine
  Models/            ← Data models
  Services/          ← Vault file management
  ViewModels/        ← SwiftUI state
  Views/             ← SwiftUI interface
  Utils/             ← Helpers
  FortressCryptApp.swift
```

## Step 4: OpenSSL Bridging Header
If using OpenSSL via C:
1. Create `FortressCrypt-Bridging-Header.h`
2. Add: `#include <openssl/evp.h>` and `#include <openssl/kdf.h>`
3. Set bridging header path in Build Settings → "Objective-C Bridging Header"

## Step 5: App Capabilities
In Signing & Capabilities, add:
- **File access** (for document picker)
- **Keychain Sharing** (for secure key storage)
- **App Groups** (if sharing encrypted data between app extensions)

## Step 6: Info.plist
Add these usage descriptions:
```xml
<key>NSFaceIDUsageDescription</key>
<string>Authenticate to unlock your vault</string>
<key>NSDocumentsFolderUsageDescription</key>
<string>Access files to encrypt and decrypt</string>
```

## Architecture Notes
- All cryptographic operations run on a background queue (never block main thread)
- The vault database itself is encrypted at rest using the user's master password
- Keychain is used to store biometric-unlock tokens (never the actual password)
- Files are streamed in 1MB chunks for memory efficiency on large files
