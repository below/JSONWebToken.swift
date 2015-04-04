import XCTest
import JWT

class JWTDecodeTests : XCTestCase {
  func testDecodingValidJWT() {
    let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiS3lsZSJ9.JdWehmn045QcErlAGWWU4pjq4ry1S0J0F2cAgmP3EI8"
    assertSuccess(decode(jwt)) { payload in
      XCTAssertEqual(payload as NSDictionary, ["name": "Kyle"])
    }
  }

  func testFailsToDecodeInvalidStringWithoutThreeSegments() {
    assertDecodeError(decode("a.b"), "Not enough segments")
  }
}

// MARK: Helpers

func assertSuccess(result:DecodeResult, closure:(Payload -> ())? = nil) {
  switch result {
  case .Success(let payload):
    if let closure = closure {
      closure(payload)
    }
  case .Failure(let failure):
    XCTFail("Failed to decode while expecting success. \(failure)")
    break
  }
}

func assertFailure(result:DecodeResult, closure:(InvalidToken -> ())? = nil) {
  switch result {
  case .Success(let payload):
    XCTFail("Decoded when expecting a failure.")
  case .Failure(let failure):
    if let closure = closure {
      closure(failure)
    }
    break
  }
}

func assertDecodeError(result:DecodeResult, error:String) {
  assertFailure(result) { failure in
    switch failure {
    case .DecodeError(let decodeError):
      if decodeError != error {
        XCTFail("Incorrect decode error \(decodeError) != \(error)")
      }
    }
  }
}