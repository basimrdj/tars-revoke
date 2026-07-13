import time
import threading
import objc
import Foundation
import AVFoundation
import Speech

def test_stt():
    print("Testing SFSpeechRecognizer...")
    recognizer = Speech.SFSpeechRecognizer.alloc().initWithLocale_(Foundation.NSLocale.localeWithLocaleIdentifier_("en-US"))
    if not recognizer:
        print("Could not initialize recognizer")
        return

    print("Requesting auth...")
    
    # We must authorize
    def auth_handler(status):
        print("Auth status:", status)
    
    Speech.SFSpeechRecognizer.requestAuthorization_(auth_handler)
    time.sleep(1)

    print("Init engine...")
    engine = AVFoundation.AVAudioEngine.alloc().init()
    request = Speech.SFSpeechAudioBufferRecognitionRequest.alloc().init()
    request.setShouldReportPartialResults_(True)

    input_node = engine.inputNode()
    format = input_node.outputFormatForBus_(0)

    def result_handler(result, error):
        if result:
            print("Recognized:", result.bestTranscription().formattedString())
        if error:
            print("Error:", error)

    task = recognizer.recognitionTaskWithRequest_resultHandler_(request, result_handler)

    def tap_block(buffer, when):
        request.appendAudioPCMBuffer_(buffer)

    input_node.installTapOnBus_bufferSize_format_block_(0, 1024, format, tap_block)

    engine.prepare()
    error = engine.startAndReturnError_(None)
    if error:
        print("Engine start error")
        return

    print("Listening for 5 seconds...")
    time.sleep(5)
    
    print("Stopping...")
    input_node.removeTapOnBus_(0)
    engine.stop()
    request.endAudio()
    task.cancel()
    print("Done.")

if __name__ == "__main__":
    test_stt()
