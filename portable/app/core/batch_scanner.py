"""
Batch Scanner & Job Queue Manager
═════════════════════════════════════════════════════════════════════
Background processing for multiple URLs/files with persistent tracking.

Features:
- ThreadPoolExecutor-based background workers
- Job queue with status tracking (pending → processing → complete)
- Real-time progress updates to database
- Resume interrupted scans
- Batch result aggregation

Author: AI-DTCTM Batch Processing Module
"""

import sqlite3
import threading
import uuid
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import List, Optional, Dict, Any
import json
import time
from core.logger import get_logger

log = get_logger(__name__)


@dataclass
class JobStatus:
    """Represents the status of a scanning job."""
    batch_id: str
    job_id: str
    status: str  # 'pending', 'processing', 'complete', 'failed'
    progress_pct: float
    scans_completed: int
    total_scans: int
    current_target: str
    eta_seconds: int
    result_json: Optional[str] = None
    error_msg: Optional[str] = None


@dataclass
class BatchResult:
    """Result from a completed scan."""
    target: str
    verdict: str
    score: float
    severity: str
    evidence: str
    scan_time_ms: float


class QueueManager:
    """Manages batch scanning job queue with background processing."""

    def __init__(self, db_path: str = "data/scan_history.db", max_workers: int = 3):
        """Initialize queue manager.

        Args:
            db_path: Path to SQLite database
            max_workers: Max number of concurrent scan workers
        """
        self.db_path = db_path
        self.max_workers = max_workers
        self.workers = ThreadPoolExecutor(max_workers=max_workers)
        self.active_jobs: Dict[str, JobStatus] = {}
        self._init_queue_table()
        self._start_background_worker()
        log.info(f"QueueManager initialized: max_workers={max_workers}")

    def _init_queue_table(self):
        """Create scan_queue table if it doesn't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    CREATE TABLE IF NOT EXISTS scan_queue (
                        job_id TEXT PRIMARY KEY,
                        batch_id TEXT NOT NULL,
                        target TEXT NOT NULL,
                        target_type TEXT NOT NULL,
                        priority INTEGER DEFAULT 5,
                        status TEXT DEFAULT 'pending',
                        progress_pct REAL DEFAULT 0,
                        result_json TEXT,
                        error_msg TEXT,
                        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                        started_at TIMESTAMP,
                        completed_at TIMESTAMP
                    )
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_batch_id ON scan_queue(batch_id)
                """)
                conn.execute("""
                    CREATE INDEX IF NOT EXISTS idx_status ON scan_queue(status)
                """)
                conn.commit()
            log.info("scan_queue table initialized")
        except Exception as e:
            log.error(f"Failed to initialize queue table: {e}")

    def enqueue(self, targets: List[str], batch_name: str,
                target_type: str = "url", priority: int = 5) -> str:
        """Submit a batch job.

        Args:
            targets: List of URLs/hashes/files to scan
            batch_name: Human-readable batch name
            target_type: Type of target ('url', 'file', 'hash')
            priority: Priority level (1-10, higher = sooner)

        Returns:
            batch_id for tracking
        """
        batch_id = f"batch_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}"

        try:
            with sqlite3.connect(self.db_path) as conn:
                for target in targets:
                    job_id = str(uuid.uuid4())
                    conn.execute("""
                        INSERT INTO scan_queue
                        (job_id, batch_id, target, target_type, priority, status)
                        VALUES (?, ?, ?, ?, ?, 'pending')
                    """, (job_id, batch_id, target, target_type, priority))
                conn.commit()

            log.info(f"Batch enqueued: {batch_id} with {len(targets)} targets")
            return batch_id
        except Exception as e:
            log.error(f"Failed to enqueue batch: {e}")
            raise

    def get_batch_status(self, batch_id: str) -> Optional[Dict[str, Any]]:
        """Get status of a batch job.

        Returns:
            {
                batch_id, status, progress_pct, scans_completed, total_scans,
                current_target, eta_seconds, results: [...]
            }
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.row_factory = sqlite3.Row

                # Get batch stats
                stats = conn.execute("""
                    SELECT
                        COUNT(*) as total,
                        SUM(CASE WHEN status = 'complete' THEN 1 ELSE 0 END) as completed,
                        SUM(CASE WHEN status = 'processing' THEN 1 ELSE 0 END) as processing,
                        COALESCE(AVG(progress_pct), 0) as avg_progress
                    FROM scan_queue
                    WHERE batch_id = ?
                """, (batch_id,)).fetchone()

                total = stats['total']
                completed = stats['completed'] or 0
                processing = stats['processing'] or 0
                progress_pct = (completed / total * 100) if total > 0 else 0

                # Get current target
                current = conn.execute("""
                    SELECT target FROM scan_queue
                    WHERE batch_id = ? AND status = 'processing'
                    LIMIT 1
                """, (batch_id,)).fetchone()

                # Estimate ETA (rough: assume each scan takes 5 seconds)
                eta_seconds = (total - completed) * 5

                # Get completed results
                results = conn.execute("""
                    SELECT result_json FROM scan_queue
                    WHERE batch_id = ? AND status = 'complete'
                    ORDER BY completed_at DESC
                """, (batch_id,)).fetchall()

                return {
                    'batch_id': batch_id,
                    'status': 'complete' if completed == total else ('processing' if processing > 0 else 'pending'),
                    'progress_pct': progress_pct,
                    'scans_completed': completed,
                    'total_scans': total,
                    'current_target': current['target'] if current else None,
                    'eta_seconds': max(0, eta_seconds),
                    'results': [json.loads(r['result_json']) for r in results if r['result_json']]
                }
        except Exception as e:
            log.error(f"Failed to get batch status: {e}")
            return None

    def cancel_job(self, batch_id: str) -> bool:
        """Cancel all pending jobs in a batch.

        Returns:
            True if successful
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'cancelled', error_msg = 'User cancelled'
                    WHERE batch_id = ? AND status = 'pending'
                """, (batch_id,))
                conn.commit()
            log.info(f"Cancelled pending jobs for batch {batch_id}")
            return True
        except Exception as e:
            log.error(f"Failed to cancel batch: {e}")
            return False

    def retry_failed(self, batch_id: str) -> int:
        """Requeue all failed scans in a batch.

        Returns:
            Number of jobs requeued
        """
        try:
            with sqlite3.connect(self.db_path) as conn:
                result = conn.execute("""
                    UPDATE scan_queue
                    SET status = 'pending', progress_pct = 0
                    WHERE batch_id = ? AND status = 'failed'
                """, (batch_id,))
                conn.commit()
                count = result.rowcount
            log.info(f"Requeued {count} failed jobs for batch {batch_id}")
            return count
        except Exception as e:
            log.error(f"Failed to retry batch: {e}")
            return 0

    def _start_background_worker(self):
        """Start background worker thread."""
        worker_thread = threading.Thread(
            target=self._process_queue,
            daemon=True,
            name="BatchQueueWorker"
        )
        worker_thread.start()
        log.info("Background queue worker started")

    def _process_queue(self):
        """Background worker: continuously process queue."""
        while True:
            try:
                # Get next pending job
                with sqlite3.connect(self.db_path) as conn:
                    job = conn.execute("""
                        SELECT * FROM scan_queue
                        WHERE status = 'pending'
                        ORDER BY priority DESC, created_at ASC
                        LIMIT 1
                    """).fetchone()

                if job:
                    job_id = job[0]
                    batch_id = job[1]
                    target = job[2]
                    target_type = job[3]

                    self._scan_target(job_id, batch_id, target, target_type)
                else:
                    # No pending jobs, sleep briefly
                    time.sleep(5)
            except Exception as e:
                log.error(f"Queue worker error: {e}")
                time.sleep(5)

    def _scan_target(self, job_id: str, batch_id: str, target: str, target_type: str):
        """Scan a single target and save result.

        Args:
            job_id: Unique job identifier
            batch_id: Batch identifier
            target: URL/file/hash to scan
            target_type: Type of target
        """
        try:
            # Update status to processing
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'processing', started_at = CURRENT_TIMESTAMP, progress_pct = 10
                    WHERE job_id = ?
                """, (job_id,))
                conn.commit()

            # Perform scan (simulated for now)
            start_time = time.time()
            result = self._do_scan(target, target_type)
            scan_time_ms = (time.time() - start_time) * 1000

            # Save result
            with sqlite3.connect(self.db_path) as conn:
                result_json = json.dumps({
                    'target': target,
                    'verdict': result.get('verdict', 'UNKNOWN'),
                    'score': result.get('score', 0.0),
                    'severity': result.get('severity', 'unknown'),
                    'scan_time_ms': scan_time_ms
                })
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'complete', progress_pct = 100,
                        result_json = ?, completed_at = CURRENT_TIMESTAMP
                    WHERE job_id = ?
                """, (result_json, job_id))
                conn.commit()

            log.info(f"Completed scan: {job_id} ({target}) - {result.get('verdict')}")
        except Exception as e:
            log.error(f"Scan failed for {job_id}: {e}")
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("""
                    UPDATE scan_queue
                    SET status = 'failed', error_msg = ?, progress_pct = 0
                    WHERE job_id = ?
                """, (str(e), job_id))
                conn.commit()

    def _do_scan(self, target: str, target_type: str) -> Dict[str, Any]:
        """Perform actual scan. Integrate with existing scanners.

        For now: returns dummy result. Replace with real scan.
        """
        # TODO: Integrate with existing URL analyzer / file scanner
        # For demo: simulate scan
        time.sleep(2)  # Simulate scanning time

        return {
            'verdict': 'CLEAN',
            'score': 0.1,
            'severity': 'low'
        }


# Global queue manager instance
_queue_manager: Optional[QueueManager] = None


def get_queue_manager() -> QueueManager:
    """Get or create global queue manager."""
    global _queue_manager
    if _queue_manager is None:
        _queue_manager = QueueManager()
    return _queue_manager
