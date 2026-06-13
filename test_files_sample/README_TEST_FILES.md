# Forensic Scanner Test Files

## 📁 10 Sample Files for Testing

Upload these files to the **Advanced Analytics → Upload Files** feature to see real malware detection in action!

---

## File Breakdown & What Gets Detected

### **1. `1_clean_hello_world.py`** ✅ CLEAN
- Simple Python script
- No suspicious patterns
- **Expected Result**: 🟢 SAFE
- **Detection**: No threats detected

---

### **2. `2_clean_readme.txt`** ✅ CLEAN
- Plain text documentation
- No code or threats
- **Expected Result**: 🟢 SAFE
- **Detection**: No threats detected

---

### **3. `3_suspicious_encoded_strings.py`** ⚠️ SUSPICIOUS
- Contains multiple base64-encoded commands
- Suspicious API call patterns
- **Expected Result**: 🟠 SUSPICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: Base64 encoded strings `base64.b64encode()`, `base64.b64decode()`
  - 🔍 AST Taint Analysis: String encoding/decoding for command hiding
  - 🔍 Entropy Analysis: High entropy from encoded data
- **Threat Type**: Command hiding, potential malware deployment

---

### **4. `4_spyware_credentials.py`** 🔴 MALICIOUS
- Keylogger implementation
- WiFi password extraction
- Browser history stealing
- Credential exfiltration
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `wifi show profile`, `keystrokes`, `passwords`, `OneDrive`, `send.*credentials`
  - 🔍 AST Analysis: Detects `pynput` keyboard logging library
  - 🔍 Hash Reputation: Known spyware patterns
  - 🔍 Entropy: High entropy in exfiltration URLs
- **Threat Type**: Spyware, Keylogger, Credential Theft

---

### **5. `5_obfuscated_malware.py`** 🔴 MALICIOUS
- DLL injection techniques
- Process injection code
- Obfuscated string manipulation
- Dynamic code execution with `exec()`
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `ctypes.CDLL`, `CreateRemoteThread`, `LoadLibrary`, `VirtualAllocEx`
  - 🔍 AST Taint Analysis: `exec()` with dynamic code, `getattr()` for obfuscation
  - 🔍 Entropy Analysis: High entropy from encoded URLs
- **Threat Type**: Malware, Code Injection, Obfuscation

---

### **6. `6_suspicious_batch.bat`** 🔴 MALICIOUS
- Disables Windows Defender
- Registry manipulation for persistence
- Scheduled task creation
- Event log deletion to hide tracks
- UAC bypass attempt
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `net stop`, `taskkill`, `del`, `wevtutil cl`, `netsh advfirewall`
  - 🔍 YARA Rules: Windows malware patterns
  - 🔍 Entropy: Command URL patterns (high entropy)
- **Threat Type**: Trojan, Persistence, Anti-forensics

---

### **7. `7_ransomware_pattern.ps1`** 🔴 MALICIOUS
- File encryption loop
- Ransom note creation
- Shadow copy deletion
- System restore disabling
- Self-deletion
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `.docx`, `.xlsx`, `.pdf`, `.locked`, `RANSOM_NOTE`, `DownloadString`
  - 🔍 AST Analysis: File encryption logic, `-bxor` bitwise operations
  - 🔍 Entropy: Command URLs
- **Threat Type**: Ransomware, File Encryption, Extortion

---

### **8. `8_cryptominer_botnet.py`** 🔴 MALICIOUS
- Cryptocurrency mining (XMRig)
- Command & Control (C2) communication
- DDoS botnet capability
- Remote payload execution
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `stratum+tcp`, `.onion`, `monero`, `pool.min`, `moneropool`
  - 🔍 AST Analysis: Socket connections to mining pools
  - 🔍 Hash Reputation: Known C2 domains/IPs
- **Threat Type**: Botnet, Cryptominer, C2 Agent

---

### **9. `9_privilege_escalation.py`** 🔴 MALICIOUS
- UAC bypass via registry
- Token theft techniques
- WMI event subscription persistence
- COM object hijacking
- Lateral movement (pass-the-hash)
- **Expected Result**: 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Regex Pattern: `CreateFileA`, `RegOpenKey`, `SetValueEx`, `pass.*hash`
  - 🔍 AST Taint Analysis: Windows API calls for privilege escalation
  - 🔍 Entropy: Command patterns
- **Threat Type**: Privilege Escalation, Lateral Movement, APT

---

### **10. `10_binary_like_suspicious.bin`** ⚠️ SUSPICIOUS
- Binary header patterns (MZ - PE header)
- High entropy content (simulates encryption)
- Suspicious embedded strings
- **Expected Result**: 🟠 SUSPICIOUS / 🔴 MALICIOUS
- **Detected By**:
  - 🔍 Entropy Analysis: Very high entropy (>7.5) indicates compression/encryption
  - 🔍 YARA Rules: PE header detection (`MZ` signature)
  - 🔍 Regex Pattern: Malware keywords and system API names
- **Threat Type**: Packed/Encrypted Malware, Binary Executable

---

## 🔍 Forensic Scanner Detection Layers

### **Layer 1: YARA Signature Matching**
Detects known malware patterns from 25+ YARA rules:
- Windows malware signatures
- Trojan patterns
- Ransomware behavior
- Botnet C2 patterns

### **Layer 2: Entropy Analysis (Shannon Entropy)**
Measures randomness of file content:
- **Low entropy** (<4.5): Plain text, code
- **Medium entropy** (4.5-7.0): Compressed files
- **High entropy** (>7.0): Encrypted, packed, or binary malware

### **Layer 3: Regular Expression Patterns** (30+ patterns)
Matches suspicious keywords:
- System commands: `cmd.exe`, `powershell`, `taskkill`, `net stop`
- File operations: `del`, `remove`, `wipe`, `encrypt`
- Network: IP addresses, domains, URLs
- APIs: `CreateRemoteThread`, `LoadLibrary`, `VirtualAlloc`
- Credentials: `password`, `hash`, `token`, `credentials`

### **Layer 4: AST Taint Analysis** (Abstract Syntax Tree)
Analyzes code structure:
- String encoding/decoding: `base64.b64encode()`, `hex.encode()`
- Dynamic execution: `exec()`, `eval()`, `__import__()`
- File operations: `open()`, `read()`, `write()`
- Network calls: `requests.get()`, `socket.connect()`
- System calls: `subprocess.run()`, `os.system()`

### **Layer 5: Hash Reputation** (MalwareBazaar Integration)
Checks file hashes against known malware database:
- If exact hash found → MALICIOUS
- Requires internet connection to MalwareBazaar API

---

## 📊 How to Test

### **Step 1: Start the App**
```bash
streamlit run main_project.py
```

### **Step 2: Navigate to Advanced Analytics**
- Click **Analytics** in sidebar
- Click **Advanced Analytics** tab

### **Step 3: Scroll to Data Management**
- Click **Upload Files** button
- A file uploader appears

### **Step 4: Upload Test Files**
- Download all 10 files from: `D:\AI_DTCTM\test_files_sample\`
- Upload each one
- See real detection results!

---

## 🎯 Expected Results Summary

| File | Expected Verdict | Detection Layers |
|------|-----------------|------------------|
| 1. hello_world.py | 🟢 SAFE | None |
| 2. readme.txt | 🟢 SAFE | None |
| 3. encoded_strings.py | 🟠 SUSPICIOUS | Regex, Entropy, AST |
| 4. spyware_credentials.py | 🔴 MALICIOUS | All 5 layers |
| 5. obfuscated_malware.py | 🔴 MALICIOUS | Regex, AST, Entropy |
| 6. suspicious_batch.bat | 🔴 MALICIOUS | YARA, Regex, Entropy |
| 7. ransomware_pattern.ps1 | 🔴 MALICIOUS | Regex, AST, Entropy |
| 8. cryptominer_botnet.py | 🔴 MALICIOUS | Regex, Hash, AST |
| 9. privilege_escalation.py | 🔴 MALICIOUS | Regex, AST, Entropy |
| 10. binary_suspicious.bin | 🟠-🔴 | Entropy, YARA, Regex |

---

## 💡 Key Insights

✅ **Why These Files Will Be Detected:**
- Real malware patterns used in the wild
- Multiple detection mechanisms (redundancy)
- Not just signature-based (also behavioral)
- Covers all major threat categories

⚠️ **False Positives:**
- Files with legitimate base64 encoding may trigger suspicious
- Legitimate system admin scripts may flag as malicious
- High entropy does NOT always mean malware (could be compressed)

🔐 **What Makes Detection Strong:**
- Combines 5 independent detection layers
- One layer alone could miss threats
- Multiple hits = higher confidence
- Real data from scan_history.db

---

## 📝 Notes

All these files are:
- ✅ **Safe to upload** (no actual malware execution)
- ✅ **Representative** (patterns from real malware)
- ✅ **Educational** (good for learning malware analysis)
- ❌ **NOT executable** (designed for analysis, not execution)

If you modify and try to RUN these files → Windows Defender may block them!
That's the point — they're realistic threat simulations.
