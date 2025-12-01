# collector/log_collector.py

import os
import time
import json
import requests

class LogCollector:
    """
    Phase 2 - Log Collector
    Reads log files incrementally and pushes lines to the ingestion server.
    """

    def __init__(self, 
                 logfile_path="/var/log/auth.log",
                 offset_path="collector/.authlog.offset",
                 ingestion_url="http://127.0.0.1:8000/ingest/log",
                 poll_interval=2):
        self.logfile_path = logfile_path
        self.offset_path = offset_path
        self.ingestion_url = ingestion_url
        self.poll_interval = poll_interval

        # Ensure offset file exists
        if not os.path.exists(self.offset_path):
            with open(self.offset_path, "w") as f:
                f.write("0")

    def _load_offset(self):
        try:
            with open(self.offset_path, "r") as f:
                return int(f.read().strip())
        except Exception:
            return 0

    def _save_offset(self, offset):
        with open(self.offset_path, "w") as f:
            f.write(str(offset))

    def send_to_ingestion(self, log_line):
        """Send log line to ingestion API."""
        payload = {"log": log_line}
        try:
            r = requests.post(
                self.ingestion_url,
                json=payload,
                 timeout=(5, 60)   # (connect_timeout, read_timeout)
            )

            r.raise_for_status()
            return True
        except Exception as e:
            print(f"[ERROR] Failed to send log: {e}")
            return False

    def process(self):
        print(f"📡 LogCollector started. Watching: {self.logfile_path}")

        while True:
            try:
                offset = self._load_offset()

                with open(self.logfile_path, "r") as lf:
                    lf.seek(offset)
                    new_offset = offset
                    lines_found = False

                    for line in lf:
                        lines_found = True
                        line = line.rstrip("\n")

                        if not line:
                            continue

                        # 🚀 Try to send the log
                        success = self.send_to_ingestion(line)
                        if not success:
                            print("⚠️ Ingestion failed. Will retry later.")
                            break

                    # 🚀 After reading all new lines: update offset ONCE
                    if lines_found:
                        new_offset = lf.tell()
                        self._save_offset(new_offset)

            except FileNotFoundError:
                print(f"❌ Log file not found: {self.logfile_path}")
            except Exception as e:
                print(f"❌ Unexpected error: {e}")

            time.sleep(self.poll_interval)
