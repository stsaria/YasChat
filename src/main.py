import sqlite3, yaml, os

os.makedirs("config", exist_ok=True)
os.makedirs("logs", exist_ok=True)

open("config/logging.yaml", "w").write("""version: 1
disable_existing_loggers: True
formatters:
    detailed:
        format: "%(asctime)s %(name)s %(levelname)s %(message)s"
handlers:
    console:
        class: logging.StreamHandler
        level: DEBUG
        formatter: detailed
        stream: ext://sys.stdout
    file:
        class: logging.handlers.RotatingFileHandler
        level: DEBUG
        formatter: detailed
        filename: logs/YasChat.log
        maxBytes: 1048576
        backupCount: 3
loggers:
    __main__:
        level: DEBUG
        handlers: [console, file]
        propagate: no
    settings:
        level: DEBUG
        handlers: [console, file]
        propagate: no
    virtualCurrencies:
        level: DEBUG
        handlers: [console, file]
        propagate: no
    bot:
        level: DEBUG
        handlers: [console, file]
        propagate: no
root:
    level: DEBUG
    handlers: [console, file]""")

from logging import getLogger, config
logger = getLogger(__name__)
config.dictConfig(yaml.load(open("config/logging.yaml").read(), Loader=yaml.SafeLoader))
os.makedirs("dbs", exist_ok=True)

import network

def main():
    network.start()
if __name__ == "__main__":
    main()