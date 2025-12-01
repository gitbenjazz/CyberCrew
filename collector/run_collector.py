# collector/run_collector.py

from collector.log_collector import LogCollector

def main():
    collector = LogCollector(
    logfile_path="test_auth.log",
    ingestion_url="http://127.0.0.1:8000/ingest/log",
    poll_interval=2
)

    collector.process()

if __name__ == "__main__":
    main()
