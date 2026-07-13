import sys
import time
import objc
import traceback
try:
    from Speech import SFSpeechRecognizer, SFSpeechURLRecognitionRequest
    from Foundation import NSURL, NSLocale
except ImportError:
    print("PyObjC Speech framework not installed. Try: pip install pyobjc-framework-Speech")
    sys.exit(1)

def test_authorization():
    print("Testing authorization...")
    status = SFSpeechRecognizer.authorizationStatus()
    print(f"Status: {status}")
    if status != 3: # 3 = authorized
        print("Requesting authorization...")
        SFSpeechRecognizer.requestAuthorization_(lambda s: print(f"New status: {s}"))
        time.sleep(2)

if __name__ == "__main__":
    test_authorization()
