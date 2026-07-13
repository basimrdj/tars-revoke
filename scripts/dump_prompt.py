import sys
import os
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import mimo_apple_realtime_assistant
from mimo_apple_realtime_assistant import RealtimeAssistant, AssistantConfig

class MockSpeaker:
    def __init__(self, *args, **kwargs): self._is_playing = False
    def is_playing(self): return self._is_playing
    def speak(self, text, *args, **kwargs): pass
    def speak_stream(self, chunks_iter, *args, **kwargs): pass
    def stop(self): pass
    def shutdown(self): pass

class MockSTT:
    def __init__(self, *args, **kwargs): pass
    def start(self): pass
    def stop(self): pass

mimo_apple_realtime_assistant.Speaker = MockSpeaker
mimo_apple_realtime_assistant.DeepgramSTT = MockSTT

config = AssistantConfig(always_respond=True)
assistant = RealtimeAssistant(config)

messages = assistant._with_runtime_addendum([{"role": "user", "content": "Hello"}])
with open("test_prompt_dump.txt", "w") as f:
    f.write(messages[0]["content"])

print(f"Dumped prompt to test_prompt_dump.txt, size: {len(messages[0]['content'])}")
