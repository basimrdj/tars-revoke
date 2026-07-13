import time
import objc
import Foundation
import Speech

def test_stt_url():
    print("Testing SFSpeechRecognizer with URL...")
    recognizer = Speech.SFSpeechRecognizer.alloc().initWithLocale_(Foundation.NSLocale.localeWithLocaleIdentifier_("en-US"))
    if not recognizer:
        print("Could not init")
        return

    # Use a dummy audio file just to see if it aborts
    url = Foundation.NSURL.fileURLWithPath_("/System/Library/Sounds/Glass.aiff")
    request = Speech.SFSpeechURLRecognitionRequest.alloc().initWithURL_(url)
    
    def result_handler(result, error):
        if result:
            print("Recognized:", result.bestTranscription().formattedString())
        if error:
            print("Error:", error)

    task = recognizer.recognitionTaskWithRequest_resultHandler_(request, result_handler)
    
    print("Waiting 3 seconds...")
    time.sleep(3)
    print("Done")

if __name__ == "__main__":
    test_stt_url()
