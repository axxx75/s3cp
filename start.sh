#!/bin/bash
cd /opt/s3cp
source venv/bin/activate
exec python -u -m  gunicorn -c gunicorn.conf.py app.app:app --log-level info --capture-output
