import multiprocessing

# Numero di worker (uno per core)
workers = multiprocessing.cpu_count()

# Host e porta
bind = "0.0.0.0:8080"
certfile = "/opt/s3cputo/app/server.crt"
keyfile = "/opt/s3cputo/app/server.key"

# Log file persistenti
errorlog = "/var/log/s3cputo/error.log"
accesslog = "/var/log/s3cputo/access.log"

# Livello di log
loglevel = "debug"

# Formato log accesso
access_log_format = '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s"'
