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
