# 📁 FILES Tab vs 🗄️ DATABASE Tab - Complete Guide

## Quick Answer

### **📁 FILES TAB** (Upload Individual Files to Scan)
These 10 files should be uploaded HERE:
```
✅ 1_clean_hello_world.py
✅ 2_clean_readme.txt
✅ 3_suspicious_encoded_strings.py
✅ 4_spyware_credentials.py
✅ 5_obfuscated_malware.py
✅ 6_suspicious_batch.bat
✅ 7_ransomware_pattern.ps1
✅ 8_cryptominer_botnet.py
✅ 9_privilege_escalation.py
✅ 10_binary_like_suspicious.bin
```

**Purpose:** Real-time malware detection on individual files
**What happens:** 
- You upload file → Scanner analyzes → Shows VERDICT immediately
- Data saved to database automatically
- Results appear in Analytics dashboard

**Safe files should ALSO be here:**
```
✅ safe_01_calculator.py
✅ safe_02_config.json
✅ safe_03_report.html
✅ safe_04_data.csv
✅ safe_05_backup_script.sh
✅ safe_06_data_analysis.py
✅ safe_07_Dockerfile
✅ safe_08_requirements.txt
✅ safe_09_database_schema.sql
✅ safe_10_api_config.yaml
```

---

### **🗄️ DATABASE TAB** (Import Database Backups)
What goes here:
```
✅ scan_history.db file (SQLite database backup)
✅ Database exports (.sql files with scan data)
✅ Bulk import of previous scan history
```

**Purpose:** Import historical scan data/backups
**What happens:**
- You upload a database file
- Forensic Scanner imports scan records
- Historical data merged with current database
- View past scans in Analytics

**NOT:** Don't upload individual malware samples here
**INSTEAD:** Use FILES tab for that

---

## Visual Workflow

```
SCENARIO 1: Testing Individual Files (Most Common)
════════════════════════════════════════════════════
1. Go to: Forensic Scanner
2. Click: 📁 FILES TAB
3. Upload: 4_spyware_credentials.py
4. Click: "Scan uploaded files"
5. See: 🔴 MALICIOUS verdict + findings
6. Check: Analytics dashboard updates


SCENARIO 2: Importing Previous Scan Data
════════════════════════════════════════════════════
1. Go to: Forensic Scanner
2. Click: 🗄️ DATABASE TAB
3. Upload: scan_history.db (backup file)
4. Click: Import
5. See: Historical scans loaded
6. Check: Analytics shows combined data


SCENARIO 3: Testing Multiple Files (What You're Doing)
════════════════════════════════════════════════════════
1. Go to: Forensic Scanner
2. Click: 📁 FILES TAB
3. Upload Multiple: 
   - 4_spyware_credentials.py
   - 6_suspicious_batch.bat
   - 7_ransomware_pattern.ps1
   - 8_cryptominer_botnet.py
   - 9_privilege_escalation.py
4. Click: "Scan uploaded files"
5. See: All 5 files scanned, results for each
6. Check: Database has 5 new records
7. Check: Analytics shows 5 new scans
```

---

## What Each Tab Does

### **📁 FILES TAB** - For Scanning

```
Input:  Individual files (.py, .bat, .sh, .pdf, .exe, etc.)
Process: Real-time forensic analysis
         ├─ YARA scanning
         ├─ Entropy analysis
         ├─ Regex pattern matching
         ├─ AST code analysis
         └─ Hash reputation check

Output: Verdict (SAFE/SUSPICIOUS/MALICIOUS)
        + Detailed findings
        + Risk score

Storage: Automatically saved to scan_history.db
```

### **🗄️ DATABASE TAB** - For Importing

```
Input:  Database file (scan_history.db or .sql dump)
Process: Parse database records
         ├─ Read scan history
         ├─ Extract findings
         ├─ Validate data
         └─ Merge with current DB

Output: All historical scans imported
        Database updated

Storage: Merged into scan_history.db
```

---

## Real Testing Steps (For You)

### **Step 1: Clean Start** ✅
- Database is EMPTY (we just cleaned it)
- No sample scans
- Ready for testing

### **Step 2: Upload Test Files** 📁
```
1. Forensic Scanner → 📁 FILES TAB
2. Upload these 5 (malicious):
   - 4_spyware_credentials.py
   - 6_suspicious_batch.bat
   - 7_ransomware_pattern.ps1
   - 8_cryptominer_botnet.py
   - 9_privilege_escalation.py
3. Click "Scan uploaded files"
4. See REAL detection results
5. Database now has 5 scans
```

### **Step 3: Verify** ✅
```
Analytics Page:
- Total Scans: 5 (was 0)
- Threats: 5 (was 0)
- Recent scans: Shows your uploads
```

### **Step 4: Upload Safe Files** ✅
```
1. Forensic Scanner → 📁 FILES TAB
2. Upload 5 safe files:
   - safe_01_calculator.py
   - safe_02_config.json
   - safe_03_report.html
   - safe_04_data.csv
   - safe_05_backup_script.sh
3. Click "Scan uploaded files"
4. See: All marked as 🟢 SAFE
5. Database now has 10 scans
```

---

## DON'T MIX THEM UP

### ❌ WRONG:
```
Upload 4_spyware_credentials.py to DATABASE TAB
(It's a malware code file, not a database!)
```

### ✅ RIGHT:
```
Upload 4_spyware_credentials.py to FILES TAB
(Real file scanning)
```

### ❌ WRONG:
```
Upload scan_history.db to FILES TAB
(It's a database backup, not a file to scan)
```

### ✅ RIGHT:
```
Upload scan_history.db to DATABASE TAB
(Import historical scan data)
```

---

## Summary Table

| What | Where | Why |
|-----|-------|-----|
| Individual files to scan (.py, .bat, .sh, etc.) | 📁 FILES TAB | Real-time analysis |
| Database backup (scan_history.db) | 🗄️ DATABASE TAB | Import history |
| Safe/clean files for testing | 📁 FILES TAB | Verify detection accuracy |
| Malicious files for testing | 📁 FILES TAB | Test threat detection |
| SQL dump of past scans | 🗄️ DATABASE TAB | Merge historical data |

---

## Your Test Files Location

```
D:\AI_DTCTM\test_files_sample\
├── 1_clean_hello_world.py ..................... → FILES TAB
├── 2_clean_readme.txt ......................... → FILES TAB
├── 3_suspicious_encoded_strings.py ........... → FILES TAB
├── 4_spyware_credentials.py .................. → FILES TAB ⭐ MALICIOUS
├── 5_obfuscated_malware.py ................... → FILES TAB ⭐ MALICIOUS
├── 6_suspicious_batch.bat .................... → FILES TAB ⭐ MALICIOUS
├── 7_ransomware_pattern.ps1 .................. → FILES TAB ⭐ MALICIOUS
├── 8_cryptominer_botnet.py ................... → FILES TAB ⭐ MALICIOUS
├── 9_privilege_escalation.py ................. → FILES TAB ⭐ MALICIOUS
├── 10_binary_like_suspicious.bin ............. → FILES TAB
├── safe_01_calculator.py ..................... → FILES TAB (safe test)
├── safe_02_config.json ....................... → FILES TAB (safe test)
└── ... (10 more safe files) .................. → FILES TAB (safe tests)
```

---

## Ready? 🚀

1. **Start app**: `streamlit run main_project.py`
2. **Go to**: Forensic Scanner
3. **Click**: 📁 FILES TAB
4. **Upload**: 5 malicious files
5. **See**: REAL detection results
6. **Verify**: Database updated, Analytics shows new scans

**Everything is SEPARATE and CLEAN now!** ✅
