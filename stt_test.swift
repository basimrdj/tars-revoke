import Foundation
import Speech

let semaphore = DispatchSemaphore(value: 0)

SFSpeechRecognizer.requestAuthorization { status in
    switch status {
    case .authorized:
        print("Authorized")
    case .denied:
        print("Denied")
    case .restricted:
        print("Restricted")
    case .notDetermined:
        print("Not determined")
    @unknown default:
        print("Unknown")
    }
    semaphore.signal()
}

semaphore.wait()
