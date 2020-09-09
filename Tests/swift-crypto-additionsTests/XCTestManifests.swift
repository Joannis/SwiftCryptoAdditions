import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(swift_crypto_additionsTests.allTests),
    ]
}
#endif
