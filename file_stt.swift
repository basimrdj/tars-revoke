import Foundation
import Speech

let args = CommandLine.arguments
if args.count < 2 {
    print("Usage: \(args[0]) <wav_file>")
    exit(1)
}

let fileURL = URL(fileURLWithPath: args[1])
guard SFSpeechRecognizer.authorizationStatus() == .authorized else {
    print("Not authorized")
    exit(1)
}

let recognizer = SFSpeechRecognizer()!
let request = SFSpeechURLRecognitionRequest(url: fileURL)
let semaphore = DispatchSemaphore(value: 0)

recognizer.recognitionTask(with: request) { result, error in
    if let result = result, result.isFinal {
        print(result.bestTranscription.formattedString)
        semaphore.signal()
    } else if let error = error {
        print("Error: \(error)")
        semaphore.signal()
    }
}

semaphore.wait()
