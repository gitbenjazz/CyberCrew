# collector/syslog_listener.py

import os
import logging
import socketserver
import signal
import sys
import requests

# Load .env if present
try:
    from dotenv import load_dotenv
    load_dotenv()
except:
    pass

# ======================
# Configuration
# ======================
SYSLOG_HOST = os.getenv("SYSLOG_HOST", "0.0.0.0")
SYSLOG_PORT = int(os.getenv("SYSLOG_PORT", "5514"))   # non-root port
INGESTION_URL = os.getenv("INGESTION_URL", "http://127.0.0.1:8000/ingest/log")
REQUEST_TIMEOUT = float(os.getenv("SYSLOG_INGEST_TIMEOUT", "3.0"))

# ======================
# Logging
# ======================
logger = logging.getLogger("syslog_listener")
logger.setLevel(logging.INFO)
handler = logging.StreamHandler(sys.stdout)
formatter = logging.Formatter(
    "[%(asctime)s] [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
handler.setFormatter(formatter)
logger.addHandler(handler)


# ======================
# Syslog Handler Class
# ======================
class SyslogUDPHandler(socketserver.BaseRequestHandler):
    def handle(self):
        raw_data = self.request[0]
        message = raw_data.decode("utf-8", errors="replace")
        src_ip, src_port = self.client_address

        logger.info(f"📥 Syslog from {src_ip}:{src_port} → {message}")

        payload = {
            "log": message,
            "source_ip": src_ip,
            "source_port": src_port,
            "transport": "udp_syslog",
        }

        try:
            r = requests.post(INGESTION_URL, json=payload, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                logger.info("➡️ Forwarded to ingestion server OK")
            else:
                logger.warning(f"⚠️ Ingestion server returned {r.status_code}: {r.text}")
        except Exception as e:
            logger.error(f"❌ Error forwarding to ingestion server: {e}")


class ThreadedUDPServer(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
    allow_reuse_address = True


# ======================
# Run listener
# ======================
def run_syslog_listener(host=SYSLOG_HOST, port=SYSLOG_PORT):
    logger.info(f"🚀 Syslog UDP listener starting on {host}:{port}")
    logger.info(f"🌐 Forwarding logs to: {INGESTION_URL}")

    server = ThreadedUDPServer((host, port), SyslogUDPHandler)

    def stop(*args):
        logger.info("🛑 Stopping syslog listener...")
        server.shutdown()

    signal.signal(signal.SIGINT, stop)
    signal.signal(signal.SIGTERM, stop)

    try:
        server.serve_forever()
    finally:
        server.server_close()
        logger.info("👋 Syslog listener stopped.")


if __name__ == "__main__":
    run_syslog_listener()
