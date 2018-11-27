import XCTest
import BCryptTests

var tests = [XCTestCaseEntry]()
tests += BCryptTests.allTests()
XCTMain(tests)