# Nuovo contenuto per app/app.py

# Punto 1: Gestione robusta directory log
import os

LOG_DIR = os.path.join(os.getcwd(), 'logs')
if not os.path.exists(LOG_DIR):
    os.makedirs(LOG_DIR)

# Punto 2: Gestione file di log Flask
from flask import Flask
import logging

app = Flask(__name__)
logging.basicConfig(filename=os.path.join(LOG_DIR, 'app.log'), level=logging.INFO)

# Punto 5: Feedback errori run_rclone
@app.route('/run_rclone')
def run_rclone():
    try:
        # Codice per eseguire rclone
        pass
    except Exception as e:
        app.logger.error(f'Errore durante l'esecuzione di rclone: {e}')
        return 'Errore durante l'esecuzione di rclone', 500

# Punto 6: Robustezza stream log job
@app.route('/stream_log')
def stream_log():
    # Codice per stream log job
    pass