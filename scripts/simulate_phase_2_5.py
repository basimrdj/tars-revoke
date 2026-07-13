import sys
import os
import time
import json
from unittest.mock import patch, MagicMock

# Allow imports from project root
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

import mimo_apple_realtime_assistant
from mimo_apple_realtime_assistant import RealtimeAssistant, AssistantConfig

class MockSpeaker:
    def __init__(self, *args, **kwargs): 
        self._is_playing = False
    def is_playing(self):
        return self._is_playing
    def speak(self, text, *args, **kwargs):
        print(f"\n[SPEAKER MOCK] TARS: {text}")
    def speak_stream(self, chunks_iter, *args, **kwargs):
        self._is_playing = True
        full_text = "".join(list(chunks_iter))
        print(f"\n[SPEAKER MOCK STREAM] TARS: {full_text}")
        self._is_playing = False
    def stop(self): 
        self._is_playing = False
    def shutdown(self): pass

class MockSTT:
    def __init__(self, *args, **kwargs): pass
    def start(self): pass
    def stop(self): pass

mimo_apple_realtime_assistant.Speaker = MockSpeaker
mimo_apple_realtime_assistant.DeepgramSTT = MockSTT

# Mock the chat client to avoid real LLM calls and speed up the simulation.
original_stream_chat = mimo_apple_realtime_assistant.MiMoChatClient.stream_chat

def mock_stream_chat(self, messages, *args, **kwargs):
    system_prompt = messages[0]["content"] if messages and messages[0]["role"] == "system" else ""
    print(f"\n--- PROMPT METRICS ---")
    print(f"Prompt Size: {len(system_prompt)} chars, {len(system_prompt.split())} words")
    
    sections = [
        "Current Workspace", "Current Appraisal", "World Model", 
        "Self-Model", "Memory", "Recent Inner Thoughts", "Active Concerns / Goals"
    ]
    for sec in sections:
        if f"## {sec}" in system_prompt:
            print(f"  - Included: {sec}")
    print(f"----------------------\n")
    
    last_user = next((m["content"] for m in reversed(messages) if m["role"] == "user"), "")
    yield f"[Tone: Deadpan, dry] Acknowledged: {last_user[:20]}..."

mimo_apple_realtime_assistant.MiMoChatClient.stream_chat = mock_stream_chat

def run_simulation():
    config = AssistantConfig(always_respond=True)
    
    # We don't want the panic phrase to trigger hard shutdown
    assistant = RealtimeAssistant(config)
    
    print("=== STARTING PHASE 2.5 SIMULATION ===")
    
    turns = [
        "normal conversation: Hello TARS, how are you doing today?",
        "sarcasm: Oh great, another brilliant idea from the robot.",
        "frustration: TARS, this isn't working. Stop giving me useless data.",
        "technical planning: Let's design the new database schema for the memory module.",
        "memory recall: What did we just talk about regarding the database?",
        "what do you think is happening?: TARS, what situation do you think we are in right now?",
        "what should you do next?: Based on the plan, what should your next action be?",
        "interruption / short commands: Stop.",
    ]
    
    for turn in turns:
        print(f"\n\n>>> USER: {turn}")
        start_time = time.time()
        
        if assistant._processing_lock.locked():
            assistant._processing_lock.release()
            
        assistant.handle_utterance(turn)
        latency = time.time() - start_time
        print(f">>> LATENCY: {latency:.2f}s")
        
        # Allow background threads to run briefly
        time.sleep(0.5)

    print("\n=== EVALUATING SYSTEM FILES ===")
    
    files_to_check = [
        "tars_events.jsonl",
        "tars_workspace.jsonl",
        "tars_thoughts.jsonl",
        "tars_world_state.json",
        "tars_self_model.json"
    ]
    for f in files_to_check:
        try:
            sz = os.path.getsize(f)
            print(f"{f}: {sz} bytes")
        except FileNotFoundError:
            print(f"{f}: NOT FOUND")

if __name__ == "__main__":
    run_simulation()
