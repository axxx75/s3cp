#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Rclone S3 Sync WebApp - Applicazione Flask per sincronizzazione bucket S3

Questa applicazione fornisce un'interfaccia web per sincronizzare file tra diversi
provider di storage S3 utilizzando rclone come backend.

Funzionalità principali:
- Listaggio bucket da provider S3 configurati
- Sincronizzazione file tra bucket diversi
- Streaming real-time dei log di sincronizzazione
- Supporto per flag aggiuntivi di rclone
- Compatibile con Python 3.6+

Autore: Axxx con l'aiuto di MiniMax Agent
Data: 2025-10-13
"""

import os
import uuid
import subprocess
import logging
import configparser
import time
from flask import Flask, render_template, request, jsonify, Response, redirect

# Import configurazioni personalizzate
from app.config import get_provider_flags, GLOBAL_FLAGS, RCLONE_CONF, Config

# =============================================================================
# CONFIGURAZIONE APPLICAZIONE FLASK
# =============================================================================

app = Flask(__name__)

# =============================================================================
# SICUREZZA: Flask-Talisman per HTTPS e Header di Sicurezza
# =============================================================================
# Utilizziamo Flask-Talisman per:
# - Forzare HTTPS (redirect automatico)
# - Abilitare HSTS
# - Impostare header di sicurezza (CSP, X-Frame-Options, ecc.)
# - Semplificare la gestione della sicurezza rispetto a middleware manuali

try:
    from flask_talisman import Talisman

    # Content Security Policy di default restrittiva, ma compatibile con la webapp
    csp = {
        'default-src': "'self'",
        'script-src': ["'self'", "'unsafe-inline'"],
        'style-src': ["'self'", "'unsafe-inline'"],
        'img-src': ["'self'", "data:"],
        'connect-src': "'self'",
    }

    talisman = Talisman(
        app,
        content_security_policy=csp,
        force_https=True,
        strict_transport_security=True,
        strict_transport_security_max_age=31536000,
        strict_transport_security_include_subdomains=True,
        strict_transport_security_preload=True,
        frame_options="DENY",
        referrer_policy="strict-origin-when-cross-origin",
        session_cookie_secure=True,
        session_cookie_http_only=True,
    )
except ImportError:
    print("⚠️  flask_talisman non installato: HTTPS e header sicurezza non applicati. Installa con 'pip install flask-talisman' per produzione.")

# Directory per i log dei job di sincronizzazione
LOG_DIR = "/tmp/rclone_jobs"

# Crea directory log se non esiste (compatibile Python 3.6)
try:
    os.makedirs(LOG_DIR, exist_ok=True)
except Exception as e:
    if not os.path.exists(LOG_DIR):
        try:
            os.makedirs(LOG_DIR)
        except Exception as dir_exc:
            print(f"❌ Errore creazione directory log {LOG_DIR}: {dir_exc}")
            logging.error(f"Errore creazione directory log {LOG_DIR}: {dir_exc}")

# ========================== LOGGING FLASK
log_handlers = [logging.StreamHandler()]
try:
    file_log_path = '/var/log/s3cputo/flask_app.log'
    os.makedirs(os.path.dirname(file_log_path), exist_ok=True)
    fh = logging.FileHandler(file_log_path, mode='a')
    log_handlers.append(fh)
except Exception as log_file_exc:
    print(f"❌ File log Flask non utilizzabile: {log_file_exc}")
    logging.error(f"File log Flask non utilizzabile: {log_file_exc}")

logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=log_handlers
)

# =============================================================================
# FUNZIONI UTILITY PER RCLONE
# =============================================================================

def get_remotes():
    """
    Legge i remotes configurati dal file di configurazione rclone.

    Returns:
        list: Lista dei nomi dei remotes configurati

    Note:
        Il file di configurazione rclone contiene le configurazioni dei provider
        di storage (AWS, GCS, ECS, ecc.) sotto forma di sezioni INI.
    """
    cfg = configparser.ConfigParser()
    if os.path.exists(RCLONE_CONF):
        cfg.read(RCLONE_CONF)
    return list(cfg.sections())

def safe_env(creds):
    """
    Prepara le variabili d'ambiente per le credenziali di accesso ai provider.

    Args:
        creds (dict): Dictionary contenente le credenziali con chiavi:
                     - access_key: Access key per S3
                     - secret_key: Secret key per S3
                     - sa_file: Service account file per GCS
                     - sa_credentials: Service account credentials per GCS
                     - gcs_project_number: Project number per GCS (12 cifre)

    Returns:
        dict: Copia dell'environment corrente con le variabili di credenziali aggiunte

    Note:
        Rclone utilizza variabili d'ambiente specifiche per autenticarsi con i vari provider.
        Questa funzione traduce le credenziali nel formato atteso da rclone.
    """
    env = os.environ.copy()

    # Credenziali S3 (AWS, ECS, MinIO, ecc.)
    if creds and creds.get("access_key"):
        env["RCLONE_S3_ACCESS_KEY_ID"] = creds["access_key"]
    if creds and creds.get("secret_key"):
        env["RCLONE_S3_SECRET_ACCESS_KEY"] = creds["secret_key"]

    # Credenziali Google Cloud Storage
    if creds and creds.get("sa_file"):
        env["RCLONE_GCS_SERVICE_ACCOUNT_FILE"] = creds["sa_file"]
    if creds and creds.get("sa_credentials"):
        env["RCLONE_GCS_SERVICE_ACCOUNT_CREDENTIALS"] = creds["sa_credentials"]

    # Project Number per GCS (obbligatorio per Service Account)
    if creds and creds.get("gcs_project_number"):
        env["RCLONE_GCS_PROJECT_NUMBER"] = creds["gcs_project_number"]

    return env

def build_remote(provider, bucket, path=''):
    """
    Costruisce la stringa remote per rclone nel formato provider:bucket/path.

    Args:
        provider (str): Nome del provider configurato in rclone
        bucket (str): Nome del bucket
        path (str, optional): Path all'interno del bucket. Default: ''

    Returns:
        str: Stringa remote nel formato "provider:bucket/path"

    Examples:
        build_remote("aws", "my-bucket", "folder/subfolder")
        # Returns: "aws:my-bucket/folder/subfolder"

        build_remote("gcs", "backup-bucket")
        # Returns: "gcs:backup-bucket"
    """
    remote = "{}:{}".format(provider, bucket)
    if path and path.strip():
        import re
        clean_path = path.strip().strip('/')
        clean_path = re.sub(r'/+', '/', clean_path)
        clean_path = re.sub(r'[@#$%^&*(){}[\]|"\'<>?`~+=]', '', clean_path)
        if clean_path:
            remote += '/' + clean_path
    return remote

def run_rclone(cmd, env):
    """
    Esegue un comando rclone in modalità asincrona e logga l'output in tempo reale.

    Args:
        cmd (list): Lista contenente il comando rclone e i suoi argomenti
        env (dict): Environment variables da utilizzare per l'esecuzione

    Returns:
        tuple: (job_id, log_file_path)
            - job_id (str): ID univoco del job
            - log_file_path (str): Path del file di log dove viene salvato l'output

    Note:
        Questa funzione avvia il processo rclone in background e ritorna immediatamente.
        Il processo continua in background e l'output viene scritto nel file di log
        per permettere lo streaming real-time all'interfaccia web.
    """
    import threading

    job_id = uuid.uuid4().hex
    log_file = os.path.join(LOG_DIR, "job_{}.log".format(job_id))
    process_error = None

    try:
        with open(log_file, "a") as f:
            f.write("[JOB {}] START: {}\n".format(job_id, ' '.join(cmd)))
            f.flush()
    except Exception as log_exc:
        print(f"❌ Errore scrittura file log: {log_exc}")

    def run_process_in_background():
        try:
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                universal_newlines=True,
                env=env,
                bufsize=1
            )
            with open(log_file, "a") as f:
                f.write("[JOB {}] PROCESS STARTED (PID: {})\n".format(job_id, proc.pid))
                f.flush()
                for line in proc.stdout:
                    f.write(line)
                    f.flush()
                proc.wait()
                f.write("[JOB {}] PROCESS COMPLETED (Exit Code: {})\n".format(job_id, proc.returncode))
                f.flush()
        except Exception as e:
            with open(log_file, "a") as f:
                f.write("[JOB {}] ERROR: {}\n".format(job_id, str(e)))
                f.flush()
    thread = threading.Thread(target=run_process_in_background, daemon=True)
    thread.start()
    time.sleep(0.5)
    if process_error:
       return job_id, log_file, process_error
    return job_id, log_file

# =============================================================================
# ROUTES FLASK - API ENDPOINTS
# =============================================================================

@app.route('/')
def index():
    """
    Route principale - renderizza la pagina web dell'applicazione.

    Returns:
        str: HTML della pagina principale con lista provider e nomi display

    Note:
        Carica i provider configurati da rclone e crea nomi display user-friendly.
        I provider vengono passati al template Jinja2 per popolare le select.
    """
    try:
        providers = get_remotes()
    except Exception as e:
        app.logger.error("Errore lettura remotes: {}".format(str(e)))
        providers = []

    provider_names = {}
    for provider in providers:
        if 'ecs' in provider.lower():
            provider_names[provider] = "ECS ({})".format(provider)
        elif 'gcs' in provider.lower():
            provider_names[provider] = "Google Cloud Storage ({})".format(provider)
        elif 'aws' in provider.lower():
            provider_names[provider] = "AWS S3 ({})".format(provider)
        else:
            provider_names[provider] = provider

    return render_template('index.html',
                         providers=providers,
                         provider_names=provider_names)

@app.route('/api/list_buckets', methods=['POST'])
def list_buckets():
    """
    API endpoint per listare i bucket di un provider.

    Expected JSON payload:
        {
            "provider": "nome_provider",
            "creds": {
                // Per HMAC (AWS, ECS, GCS-HMAC):
                "access_key": "access_key",
                "secret_key": "secret_key"
                // Per GCS Service Account:
                "sa_credentials": "{\"type\": \"service_account\", ...}"
            }
        }

    Returns:
        JSON: {"buckets": ["bucket1", "bucket2", ...]} oppure {"error": "messaggio"}

    Note:
        Utilizza il comando "rclone lsd provider:" per listare le directory (bucket)
        al livello radice del provider. Le credenziali vengono passate tramite
        variabili d'ambiente specifiche per il tipo di autenticazione.
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dati JSON mancanti"}), 400

        provider = data.get("provider")
        creds = data.get("creds", {})

        if not provider:
            return jsonify({"error": "Provider mancante"}), 400

        app.logger.info("Lista bucket per provider: {}".format(provider))

        has_hmac = creds.get('access_key') and creds.get('secret_key')
        has_sa_creds = creds.get('sa_credentials')
        has_sa_file = creds.get('sa_file')
        has_project_number = creds.get('gcs_project_number')

        if not (has_hmac or has_sa_creds or has_sa_file):
            app.logger.error("Nessuna credenziale valida fornita")
            return jsonify({"error": "Credenziali mancanti: inserisci Access/Secret Key o Service Account JSON"}), 400

        is_gcs = provider and provider.lower().find('gcs') != -1
        if is_gcs and (has_sa_creds or has_sa_file) and not has_project_number:
            app.logger.error("Project Number mancante per GCS Service Account")
            return jsonify({"error": "Project Number GCS obbligatorio (12 cifre) per Service Account"}), 400

        env = safe_env(creds)
        cmd = ["rclone", "lsd", "{}:".format(provider), "-vv"] + get_provider_flags(provider)

        app.logger.info("Comando: {}".format(' '.join(cmd)))

        if has_hmac:
            app.logger.info("Modalità autenticazione: HMAC (Access/Secret Key)")
            app.logger.info("Access Key length: {}".format(len(creds.get('access_key', ''))))
        elif has_sa_creds:
            app.logger.info("Modalità autenticazione: Service Account JSON (inline)")
            app.logger.info("SA JSON length: {}".format(len(creds.get('sa_credentials', ''))))
            try:
                import json
                parsed_sa = json.loads(creds.get('sa_credentials'))
                app.logger.info("SA JSON type: {}".format(parsed_sa.get('type', 'unknown')))
                app.logger.info("SA JSON project_id: {}".format(parsed_sa.get('project_id', 'unknown')))
            except json.JSONDecodeError as e:
                app.logger.error("SA JSON non valido: {}".format(str(e)))
                return jsonify({"error": "Service Account JSON non valido: {}".format(str(e))}), 400
        elif has_sa_file:
            app.logger.info("Modalità autenticazione: Service Account File")
            app.logger.info("SA File path: {}".format(creds.get('sa_file')))

        env_vars = []
        if 'RCLONE_S3_ACCESS_KEY_ID' in env:
            env_vars.append('RCLONE_S3_ACCESS_KEY_ID')
        if 'RCLONE_S3_SECRET_ACCESS_KEY' in env:
            env_vars.append('RCLONE_S3_SECRET_ACCESS_KEY')
        if 'RCLONE_GCS_SERVICE_ACCOUNT_CREDENTIALS' in env:
            env_vars.append('RCLONE_GCS_SERVICE_ACCOUNT_CREDENTIALS')
        if 'RCLONE_GCS_SERVICE_ACCOUNT_FILE' in env:
            env_vars.append('RCLONE_GCS_SERVICE_ACCOUNT_FILE')
        if 'RCLONE_GCS_PROJECT_NUMBER' in env:
            env_vars.append('RCLONE_GCS_PROJECT_NUMBER')
            app.logger.info("GCS Project Number: {}".format(env.get('RCLONE_GCS_PROJECT_NUMBER')))
        app.logger.info("Environment variables set: {}".format(', '.join(env_vars)))

        app.logger.info("Esecuzione comando rclone...")
        output = subprocess.check_output(
            cmd,
            env=env,
            universal_newlines=True,
            timeout=60,
            stderr=subprocess.STDOUT
        )

        app.logger.info("Output rclone ricevuto ({} caratteri)".format(len(output)))

        output_preview = output[:1000] + "..." if len(output) > 1000 else output
        app.logger.debug("Output rclone: {}".format(output_preview))

        buckets = []
        for line_num, line in enumerate(output.splitlines()):
            line = line.strip()
            if line:
                app.logger.debug("Parsing line {}: {}".format(line_num, line))
                if line.startswith("20") and ("DEBUG :" in line or "INFO :" in line or "ERROR :" in line):
                    app.logger.debug("Riga di debug ignorata")
                    continue
                parts = line.split()
                if len(parts) >= 5 and parts[0] == "-1" and len(parts[1]) == 10 and ":" in parts[2]:
                    bucket_name = parts[-1]
                    if bucket_name and bucket_name not in ["*", "active", "routines"] and not bucket_name.startswith('"'):
                        buckets.append(bucket_name)
                        app.logger.debug("Bucket GCS trovato: {}".format(bucket_name))
                    else:
                        app.logger.debug("Nome bucket non valido ignorato: {}".format(bucket_name))
                elif len(parts) >= 5 and not parts[0].startswith("20") and not line.startswith("-1"):
                    bucket_name = parts[-1]
                    if bucket_name and not bucket_name.startswith('"') and not bucket_name.endswith('"'):
                        buckets.append(bucket_name)
                        app.logger.debug("Bucket S3 trovato: {}".format(bucket_name))
                else:
                    app.logger.debug("Riga ignorata (formato non riconosciuto): {}".format(line))

        app.logger.info("Parsing completato: {} bucket trovati".format(len(buckets)))
        return jsonify({"buckets": buckets})

    except subprocess.CalledProcessError as e:
        error_output = getattr(e, 'output', 'Nessun output disponibile')
        app.logger.error("Errore comando rclone (exit code {}): {}".format(e.returncode, error_output))

        if "NoCredentialsError" in error_output:
            error_msg = "Credenziali non valide o mancanti per il provider"
        elif "AccessDenied" in error_output:
            error_msg = "Accesso negato: verifica le credenziali e i permessi"
        elif "InvalidAccessKeyId" in error_output:
            error_msg = "Access Key non valida"
        elif "SignatureDoesNotMatch" in error_output:
            error_msg = "Secret Key non valida"
        elif "authentication failed" in error_output.lower():
            error_msg = "Autenticazione fallita: verifica le credenziali"
        else:
            error_msg = "Errore rclone: {}".format(error_output[:200])

        return jsonify({"error": error_msg}), 400

    except subprocess.TimeoutExpired as e:
        app.logger.error("Timeout comando rclone dopo 60 secondi")
        return jsonify({"error": "Timeout: operazione troppo lenta. Verifica la connessione e le credenziali"}), 504

    except Exception as e:
        app.logger.error("Errore generico in list_buckets: {}".format(str(e)))
        app.logger.exception("Stack trace completo:")
        return jsonify({"error": "Errore interno: {}".format(str(e))}), 500

@app.route('/api/copy', methods=['POST'])
def copy():
    """
    API endpoint per avviare una sincronizzazione tra bucket.

    Expected JSON payload:
        {
            "src_provider": "provider_sorgente",
            "dst_provider": "provider_destinazione",
            "src_bucket": "bucket_sorgente",
            "dst_bucket": "bucket_destinazione",
            "src_path": "path_sorgente_opzionale",
            "dst_path": "path_destinazione_opzionale",
            "src_creds": {
                // Per provider HMAC (AWS, ECS, etc.):
                "access_key": "...", "secret_key": "..."
                // Per provider GCS con Service Account:
                "sa_credentials": "{'type':'service_account',...}"
            },
            "dst_creds": { /* stesso formato di src_creds */ },
            "additional_flags": ["--dry-run", "--verbose", ...]
        }

    Returns:
        JSON: {"job_id": "job_id"} oppure {"error": "messaggio"}

    Note:
        Avvia un job di sincronizzazione asincrono utilizzando "rclone sync".
        Il job viene eseguito in background e l'output viene loggato in un file
        che può essere streamato tramite l'endpoint /api/log/<job_id>.

        Supporta autenticazione multipla:
        - HMAC: access_key + secret_key (per AWS, ECS, MinIO, etc.)
        - Service Account: sa_credentials (JSON compatto per GCS)
    """
    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Dati JSON mancanti"}), 400

        src_provider = data.get('src_provider')
        dst_provider = data.get('dst_provider')
        src_bucket = data.get('src_bucket')
        dst_bucket = data.get('dst_bucket')
        src_path = data.get('src_path', '')
        dst_path = data.get('dst_path', '')
        src_creds = data.get('src_creds', {})
        dst_creds = data.get('dst_creds', {})
        additional_flags = data.get('additional_flags', [])

        if not all([src_provider, dst_provider, src_bucket, dst_bucket]):
            return jsonify({"error": "Parametri mancanti"}), 400

        is_src_gcs = src_provider and src_provider.lower().find('gcs') != -1
        if is_src_gcs:
            has_src_hmac = src_creds.get('access_key') and src_creds.get('secret_key')
            has_src_sa = src_creds.get('sa_credentials') or src_creds.get('sa_file')
            has_src_project_number = src_creds.get('gcs_project_number')

            if has_src_sa and not has_src_project_number:
                app.logger.error("Project Number mancante per GCS sorgente")
                return jsonify({"error": "Project Number GCS obbligatorio per Service Account sorgente"}), 400

            app.logger.info("GCS sorgente - Project Number: {}".format(has_src_project_number))

        is_dst_gcs = dst_provider and dst_provider.lower().find('gcs') != -1
        if is_dst_gcs:
            has_dst_hmac = dst_creds.get('access_key') and dst_creds.get('secret_key')
            has_dst_sa = dst_creds.get('sa_credentials') or dst_creds.get('sa_file')
            has_dst_project_number = dst_creds.get('gcs_project_number')

            if has_dst_sa and not has_dst_project_number:
                app.logger.error("Project Number mancante per GCS destinazione")
                return jsonify({"error": "Project Number GCS obbligatorio per Service Account destinazione"}), 400

            app.logger.info("GCS destinazione - Project Number: {}".format(has_dst_project_number))

        src = build_remote(src_provider, src_bucket, src_path)
        dst = build_remote(dst_provider, dst_bucket, dst_path)

        app.logger.info("Remote costruiti - SRC: '{}', DST: '{}'".format(src, dst))

        env = os.environ.copy()
        env.update(safe_env(src_creds))
        env.update(safe_env(dst_creds))

        src_flags = get_provider_flags(src_provider)
        dst_flags = get_provider_flags(dst_provider)

        all_flags = src_flags + dst_flags + GLOBAL_FLAGS + additional_flags
        flags = list(set(all_flags))

        cmd = ["rclone", "sync", src, dst] + flags

        app.logger.info("Avvio sincronizzazione: {} -> {}".format(src, dst))
        app.logger.info("Comando completo: {}".format(' '.join(cmd)))

        app.logger.info("Avvio processo rclone in background...")
        job_id, log_file = run_rclone(cmd, env)
        app.logger.info("Job creato con ID: {} - Log: {}".format(job_id, log_file))

        return jsonify({"job_id": job_id})

    except Exception as e:
        app.logger.error("Errore copy: {}".format(str(e)))
        return jsonify({"error": str(e)}), 500

@app.route('/api/log/<job_id>')
def stream_log(job_id):
    """
    API endpoint per streaming real-time dei log di un job.

    Args:
        job_id (str): ID del job di cui streammare i log

    Returns:
        Response: Server-Sent Events stream con i log del job

    Note:
        Utilizza Server-Sent Events (SSE) per inviare i log in tempo reale
        al browser. Il client può aprire una connessione EventSource per
        ricevere gli aggiornamenti automaticamente.

        Formato eventi:
        - "data: messaggio_log\n\n" per ogni riga di log
        - "data: [STREAM_END]\n\n" quando il job è completato
    """
    def generate():
        log_file = os.path.join(LOG_DIR, "job_{}.log".format(job_id))
        last_size = 0

        timeout = 30
        start_time = time.time()

        while not os.path.exists(log_file) and (time.time() - start_time) < timeout:
            time.sleep(0.5)

        if not os.path.exists(log_file):
            yield "data: Errore: File di log non trovato\n\n"
            return

        yield "data: Connesso al log del job {}\n\n".format(job_id)

        job_completed = False
        while not job_completed:
            try:
                if os.path.exists(log_file):
                    with open(log_file, 'r') as f:
                        f.seek(last_size)
                        new_content = f.read()

                        if new_content:
                            for line in new_content.splitlines():
                                if line.strip():
                                    yield "data: {}\n\n".format(line)

                            last_size = f.tell()

                            completion_indicators = [
                                'transferred:', 'errors:', 'checks:', 'elapsed time:'
                            ]
                            if any(indicator in new_content.lower() for indicator in completion_indicators):
                                time.sleep(2)
                                job_completed = True

                if not job_completed:
                    time.sleep(1)

                if time.time() - start_time > 3600:
                    yield "data: Timeout raggiunto\n\n"
                    break

            except Exception as e:
                yield "data: Errore: {}\n\n".format(str(e))
                break

        yield "data: [STREAM_END]\n\n"

    return Response(generate(), mimetype="text/event-stream")

@app.route('/api/jobs')
def jobs():
    """
    API endpoint per listare i job disponibili.

    Returns:
        JSON: {
            "active_jobs": ["job_id1", "job_id2", ...],
            "total_jobs": numero_totale
        }

    Note:
        Elenca tutti i file di log presenti nella directory LOG_DIR.
        Non distingue tra job attivi e completati per semplicità.
    """
    try:
        log_files = []

        if os.path.exists(LOG_DIR):
            for filename in os.listdir(LOG_DIR):
                if filename.startswith("job_") and filename.endswith(".log"):
                    job_id = filename[4:-4]
                    log_files.append(job_id)

        return jsonify({
            "active_jobs": log_files,
            "total_jobs": len(log_files)
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/md/<path:filename>")
def show_markdown(filename):
    import markdown, os
    base_dir = app.root_path
    file_path = os.path.join(base_dir, filename)

    if not os.path.isfile(file_path):
        return "File non trovato", 404

    with open(file_path, "r", encoding="utf-8") as f:
        html = markdown.markdown(f.read())

    return f"""
    <html>
      <head><title>{filename}</title></head>
      <body style="max-width:800px; margin:auto; font-family:sans-serif;">
        {html}
      </body>
    </html>
    """

# =============================================================================
# AVVIO APPLICAZIONE
# =============================================================================

if __name__ == "__main__":
    """
    Entry point principale dell'applicazione.

    Esegue test di sistema e avvia il server Flask in modalità debug.
    """
    print("🚀 Avvio Rclone S3 Sync WebApp")
    print("📂 Log directory: {}".format(LOG_DIR))
    print("⚙️  Rclone config: {}".format(RCLONE_CONF))

    try:
        subprocess.run(["rclone", "version"], capture_output=True, check=True)
        print("✅ rclone trovato e funzionante")
    except Exception:
        print("❌ rclone non trovato o non funzionante")

    if os.path.exists(RCLONE_CONF):
        try:
            remotes = get_remotes()
            print("✅ Config trovata con {} remotes: {}".format(
                len(remotes), ', '.join(remotes[:5])
            ))
        except Exception as e:
            print("⚠️  Errore lettura config: {}".format(str(e)))
    else:
        print("⚠️  Config non trovata: {}".format(RCLONE_CONF))

    config = Config()

    ssl_enabled = getattr(config, 'SSL_ENABLED', False)
    ssl_cert_path = getattr(config, 'SSL_CERT_PATH', '')
    ssl_key_path = getattr(config, 'SSL_KEY_PATH', '')

    protocol = "https" if ssl_enabled else "http"
    ssl_context = None

    if ssl_enabled:
        try:
            if ssl_cert_path and ssl_key_path and os.path.exists(ssl_cert_path) and os.path.exists(ssl_key_path):
                ssl_context = (ssl_cert_path, ssl_key_path)
                print("✅ Certificati SSL trovati")
            else:
                print("⚠️  Certificati SSL non trovati, generazione certificato auto-firmato...")
                ssl_context = 'adhoc'
                print("📝 ATTENZIONE: Usato certificato auto-firmato (solo per sviluppo)")
        except Exception as e:
            print("❌ Errore configurazione SSL: {}".format(str(e)))
            print("🔄 Fallback a HTTP...")
            ssl_enabled = False
            protocol = "http"

    print("\n🌐 Server in ascolto su {}://{}:{}".format(protocol, config.HOST, config.PORT))
    print("📖 Documentazione API disponibile negli endpoint /api/*")

    if ssl_enabled:
        print("🔒 SSL/HTTPS abilitato")
        if ssl_context == 'adhoc':
            print("⚠️  Certificato auto-firmato (accetta l'avviso nel browser)")

    app.run(
        host=config.HOST,
        port=config.PORT,
        debug=config.DEBUG,
        ssl_context=ssl_context
    )
