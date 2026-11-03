import XCTest

@MainActor
final class BifrostTests: XCTestCase {
    func testBackgroundDiscardsSession() {
        let app = XCUIApplication()
        app.launch()
        let address = app.textFields["peerURL"]
        address.tap()
        address.typeText("https://192.0.2.1?token=test")
        app.buttons["connect"].tap()
        XCTAssertTrue(app.buttons["disconnect"].waitForExistence(timeout: 5))
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.buttons["connect"].waitForExistence(timeout: 5))
        XCTAssertTrue(app.staticTexts["sessionStatus"].label.contains("left foreground"))
        XCTAssertFalse(app.buttons["approve"].exists)
    }

    func testListenerPublishesItsBoundPortAndStopsOnBackground() {
        let app = XCUIApplication()
        app.launch()
        app.segmentedControls["connectionMode"].buttons["Listen"].tap()
        let address = app.textFields["listenAddress"]
        address.tap()
        address.typeText(String(repeating: XCUIKeyboardKey.delete.rawValue, count: "0.0.0.0:7071".count) + "127.0.0.1:0")
        app.buttons["connect"].tap()
        let joinURL = app.staticTexts["listenerURL"]
        XCTAssertTrue(joinURL.waitForExistence(timeout: 10))
        XCTAssertTrue(joinURL.label.hasPrefix("ws://127.0.0.1:"))
        XCTAssertFalse(joinURL.label.contains(":0/"))
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.buttons["connect"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.staticTexts["listenerURL"].exists)
        XCTAssertTrue(app.staticTexts["sessionStatus"].label.contains("left foreground"))
    }

    func testLiveConsentAndBackgroundCleanup() throws {
        guard let endpoint = ProcessInfo.processInfo.environment["BIFROST_TEST_SERVER_URL"] else {
            throw XCTSkip("Set TEST_RUNNER_BIFROST_TEST_SERVER_URL to a listening consumer for device integration.")
        }
        let app = XCUIApplication()
        app.launch()
        addUIInterruptionMonitor(withDescription: "Local network access") { alert in
            let allow = alert.buttons["Allow"]
            if allow.exists { allow.tap(); return true }
            return false
        }
        let address = app.textFields["peerURL"]
        address.tap()
        address.typeText(endpoint)
        app.buttons["connect"].tap()
        app.tap()
        XCTAssertTrue(app.buttons["approve"].waitForExistence(timeout: 30))
        XCTAssertFalse(app.staticTexts["sessionStatus"].label == "Connected")
        app.buttons["approve"].tap()
        let connected = NSPredicate(format: "label == %@", "Connected")
        expectation(for: connected, evaluatedWith: app.staticTexts["sessionStatus"])
        waitForExpectations(timeout: 15)
        XCTAssertTrue(app.buttons["disconnect"].exists)
        XCUIDevice.shared.press(.home)
        app.activate()
        XCTAssertTrue(app.buttons["connect"].waitForExistence(timeout: 5))
        XCTAssertFalse(app.buttons["approve"].exists)
    }
}
