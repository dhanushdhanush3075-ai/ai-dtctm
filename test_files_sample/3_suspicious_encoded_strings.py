#!/usr/bin/env python3
import base64
import subprocess

# SUSPICIOUS: Encoded payload
payload = "cmd.exe /c ipconfig"
encoded = base64.b64encode(payload.encode()).decode()

# SUSPICIOUS: Base64 decoding and execution
def execute_command():
    decoded = base64.b64decode(encoded).decode()
    print("Executing:", decoded)
    # This pattern is often used in malware to hide commands

# SUSPICIOUS: Multiple base64 strings that decode to system commands
cmd1 = "cG93ZXJzaGVsbCAtRW5jb2RlZENvbW1hbmQgVwBBAFcAdwBBAA=="
cmd2 = "Y21kIC9jIGRpciBj"
cmd3 = "cGluZyAxOTIuMTY4LjEuMQ=="

def suspicious_function():
    for cmd in [cmd1, cmd2, cmd3]:
        data = base64.b64decode(cmd)
        print(f"Found encoded command: {data}")

if __name__ == "__main__":
    suspicious_function()
