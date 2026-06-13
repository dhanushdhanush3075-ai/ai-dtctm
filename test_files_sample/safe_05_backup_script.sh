#!/bin/bash
# Legitimate Backup Script
# No malicious code - just standard system administration

echo "Starting backup process..."

# Set variables
BACKUP_DIR="/backups"
SOURCE_DIR="/home/user/documents"
DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_FILE="backup_${DATE}.tar.gz"

# Create backup directory if it doesn't exist
if [ ! -d "$BACKUP_DIR" ]; then
    mkdir -p "$BACKUP_DIR"
    echo "Created backup directory"
fi

# Compress and backup
echo "Compressing files..."
tar -czf "$BACKUP_DIR/$BACKUP_FILE" "$SOURCE_DIR" 2>/dev/null

if [ $? -eq 0 ]; then
    echo "Backup successful: $BACKUP_FILE"

    # Calculate file size
    SIZE=$(du -h "$BACKUP_DIR/$BACKUP_FILE" | cut -f1)
    echo "Backup size: $SIZE"

    # List recent backups
    echo "Recent backups:"
    ls -lh "$BACKUP_DIR" | tail -5
else
    echo "Backup failed"
    exit 1
fi

echo "Backup process completed at $(date)"
