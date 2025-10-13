#!/bin/bash
cd /opt/s3cputo
source venv/bin/activate
exec python -u -m  gunicorn -c gunicorn.conf.py app.app:app --log-level debug --capture-output
