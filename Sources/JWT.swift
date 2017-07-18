import Foundation
import CommonCrypto

public typealias Payload = [String: Any]

/// The supported Algorithms
public enum Algorithm: CustomStringConvertible {
  /// No Algorithm, i-e, insecure
  case none

  /// HMAC using SHA-256 hash algorithm
  case hs256(Data)

  /// HMAC using SHA-384 hash algorithm
  case hs384(Data)

  /// HMAC using SHA-512 hash algorithm
  case hs512(Data)

  public var description: String {
    switch self {
    case .none:
      return "none"
    case .hs256:
      return "HS256"
    case .hs384:
      return "HS384"
    case .hs512:
      return "HS512"
    }
  }

  /// Sign a message using the algorithm
  func sign(_ message: String) -> String {
    func signHS(_ key: Data, variant: Int) -> String {
      
      var digestLength : Int!
      switch variant {
      case kCCHmacAlgSHA256:
        digestLength = Int(CC_SHA256_DIGEST_LENGTH)
      case kCCHmacAlgSHA384:
        digestLength = Int(CC_SHA384_DIGEST_LENGTH)
      case kCCHmacAlgSHA512:
        digestLength = Int(CC_SHA512_DIGEST_LENGTH)
      default:
        return ""
      }
      
      let signature = UnsafeMutablePointer<CUnsignedChar>.allocate(capacity: digestLength)
      defer { signature.deallocate(capacity: digestLength) }
      
      let messageData = message.data(using: String.Encoding.utf8, allowLossyConversion: false)!

      messageData.withUnsafeBytes { dataBytes in
        key.withUnsafeBytes { keyBytes in
          CCHmac(CCHmacAlgorithm(variant), keyBytes, key.count, dataBytes, messageData.count, signature)
        }
      }
      
      let result = Data(bytes: signature, count: digestLength)

      return base64encode(result)
    }

    switch self {
    case .none:
      return ""

    case .hs256(let key):
      return signHS(key, variant: kCCHmacAlgSHA256)

    case .hs384(let key):
      return signHS(key, variant: kCCHmacAlgSHA384)

    case .hs512(let key):
      return signHS(key, variant: kCCHmacAlgSHA512)
    }
  }

  /// Verify a signature for a message using the algorithm
  func verify(_ message: String, signature: Data) -> Bool {
    return sign(message) == base64encode(signature)
  }
}
