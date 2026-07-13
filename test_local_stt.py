import threading
import time
import objc
import Foundation
import Speech
import sounddevice as sd
import soundfile as sf
import tempfile
import numpy as np

def test_local_stt():
    print("Recording 3 seconds...")
    audio = sd.rec(int(3 * 16000), samplerate=16000, channels=1, dtype='float32')
    sd.wait()
    
    with tempfile.NamedTemporaryFile(suffix=".wav", delete=False) as f:
        sf.write(f.name, audio, 16000)
        temp_path = f.name
        
    print("Transcribing...")
    recognizer = Speech.SFSpeechRecognizer.alloc().initWithLocale_(Foundation.NSLocale.localeWithLocaleIdentifier_("en-US"))
    url = Foundation.NSURL.fileURLWithPath_(temp_path)
    request = Speech.SFSpeechURLRecognitionRequest.alloc().initWithURL_(url)
    request.setRequiresOnDeviceRecognition_(True)
    
    final_text = []
    done = threading.Event()
    
    def result_handler(result, error):
        if result:
            if result.isFinal():
                final_text.append(result.bestTranscription().formattedString())
                done.set()
        if error:
            print("STT Error:", error.localizedDescription())
            done.set()

    task = recognizer.recognitionTaskWithRequest_resultHandler_(request, result_handler)
    done.wait(timeout=5)
    
    print("Result:", "".join(final_text))

if __name__ == "__main__":
    test_local_stt()
