import XCTest
import swift_crypto_additions

final class swift_crypto_additionsTests: XCTestCase {
    func testExample() {
        let serverPrivateKey = RSA.Signing.PrivateKey()
        let clientPrivateKey = RSA.Signing.PrivateKey()
        
        let serverPublicKey = serverPrivateKey.formPublicKey(generator: .generator2)
        let clientPublicKey = clientPrivateKey.formPublicKey(generator: .generator2)
        
        let serverSecret = serverPrivateKey.formSecret(with: clientPublicKey)
        let clientSecret = clientPrivateKey.formSecret(with: serverPublicKey)
        
        XCTAssertEqual(serverSecret.asArbitraryInt(), clientSecret.asArbitraryInt())
    }

    static var allTests = [
        ("testExample", testExample),
    ]
}
