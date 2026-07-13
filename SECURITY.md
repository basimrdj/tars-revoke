# Security Policy

This project is a local voice-agent research prototype. The sensitive assets
are usually not source code; they are runtime state, memory stores,
credentials, generated audio, and personal logs.

## Keep Out of Git

- `.env` files and provider keys
- SQLite memory databases
- JSONL thought/event/workspace logs
- generated audio and transcripts
- screen/camera captures
- personal profile or conversation exports
- build-worker credentials or shell histories

## Reporting Issues

Use public issues for ordinary bugs. For sensitive security reports, avoid
posting raw keys, private logs, audio, personal memory rows, or screenshots.

## Capability Claims

Do not present this project as conscious, sentient, biometric security, or
production-safe autonomy. It is an inspectable agent-memory architecture and
voice runtime prototype.
