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

# Configurazione Flask (Python 3.6 compatible)
class Config(object):
    """Configurazione base Flask"""
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    DEBUG = os.environ.get('FLASK_DEBUG', 'True').lower() == 'true'
    HOST = os.environ.get('FLASK_HOST', '0.0.0.0')
    PORT = int(os.environ.get('FLASK_PORT', 8080))

    SSL_ENABLED = os.environ.get('SSL_ENABLED', 'False').lower() == 'true'
    SSL_CERT_PATH = os.environ.get('SSL_CERT_PATH', '')
    SSL_KEY_PATH = os.environ.get('SSL_KEY_PATH', '')
