import multiprocessing
import os

# === 🔐 CONFIGURAZIONE SSL ===
# Percorsi certificati SSL (usati da Gunicorn *e* esportati per Flask)
SSL_CERT_PATH = "/opt/s3cputo/app/server.crt"
SSL_KEY_PATH = "/opt/s3cputo/app/server.key"

# Esporta le variabili d'ambiente così Flask le vede nel config.py
os.environ["SSL_CERT_PATH"] = SSL_CERT_PATH
os.environ["SSL_KEY_PATH"] = SSL_KEY_PATH

# Gunicorn userà direttamente questi file per HTTPS
certfile = SSL_CERT_PATH
keyfile = SSL_KEY_PATH

# Numero di worker (uno per core)
workers = multiprocessing.cpu_count()

# Host e porta
bind = [ "0.0.0.0:8080" ]

# Log file persistenti
errorlog = "/var/log/s3cputo/error.log"
accesslog = "/var/log/s3cputo/access.log"

# Livello di log
loglevel = "debug"

# Formato log accesso
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'

# --- Opzioni avanzate ---
# Numero massimo richieste per worker prima del restart (opzionale)
max_requests = 1000
max_requests_jitter = 50

# Timeout
timeout = 30
graceful_timeout = 30

# Keep-alive
keepalive = 2

# --- Directory di lavoro ---
chdir = os.path.dirname(os.path.abspath(__file__))  # sempre lavorare nella cartella del progetto
(venv) [root@vmgclalpr1750 /opt/s3cputo]# cat app/config.py
import os

# Percorso file di configurazione Rclone
RCLONE_CONF = "/root/.config/rclone/rclone.conf"

# Flag specifici per provider (compatibile Python 3.6)
PROVIDER_FLAGS = {
    "ECS_OLD": ["--no-check-certificate", "--s3-env-auth", "--config={}".format(RCLONE_CONF)],
    "ECS_NEW": ["--no-check-certificate", "--s3-env-auth", "--config={}".format(RCLONE_CONF)],
    "GCS": ["--metadata", "--use-server-modtime", "--gcs-bucket-policy-only"],
    "AWS": ["--config={}".format(RCLONE_CONF)],
    "MINIO": ["--config={}".format(RCLONE_CONF)],
    "DIGITALOCEAN": ["--config={}".format(RCLONE_CONF)],
    "WASABI": ["--config={}".format(RCLONE_CONF)],
    "BACKBLAZE": ["--config={}".format(RCLONE_CONF)],
}

# Flag comuni a tutti i provider
GLOBAL_FLAGS = [
    "--update",
    "--progress",
    "--low-level-retries=10",
    "--retries=5",
    "--stats=15",
    "--stats-log-level=NOTICE",
    "--log-level=NOTICE",
    "--checkers=16",
    "--transfers=8",
]

def get_provider_flags(provider):
    """Restituisce i flag specifici del provider"""
    return PROVIDER_FLAGS.get(provider.upper(), [])

# Configurazione Flask
class Config(object):
    """Configurazione base Flask"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    PORT = int(os.environ.get('FLASK_PORT', 8080))

    SSL_ENABLED = os.environ.get('SSL_ENABLED', 'False').lower() == 'true'
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '')
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH', '')
