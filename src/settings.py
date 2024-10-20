import base64, yaml, json, os
from logging import getLogger, config
logger = getLogger(__name__)
config.dictConfig(yaml.load(open("config/logging.yaml", encoding="utf-8").read(), Loader=yaml.SafeLoader))

class Settings:
    settings = None
    def __init__(self, settingsFile:str="config/settings.json"):
        if os.path.isfile(settingsFile):
            self.settings = json.load(open(settingsFile, encoding="utf-8"))
            logger.info("Config loaded")
        else:
            self.settings = {
                "bootstrapNodes": [{"ip":input("BootstrapIp:"), "port":int(input("BootstrapPort:"))}],
                "stunServers": [
                    {"ip":"stun.l.google.com", "port":19302}, 
                    {"ip":"stun.l.google.com", "port":5349},
                    {"ip":"stun1.l.google.com", "port":3478},
                    {"ip":"stun1.l.google.com", "port":5349},
                    {"ip":"stun2.l.google.com", "port":19302},
                    {"ip":"stun2.l.google.com", "port":5349},
                    {"ip":"stun3.l.google.com", "port":3478},
                    {"ip":"stun3.l.google.com", "port":5349},
                    {"ip":"stun4.l.google.com", "port":19302},
                    {"ip":"stun4.l.google.com", "port":5349}
                ]
            }
            json.dump(self.settings, open(settingsFile, encoding="utf-8", mode="w"), indent=4)
            logger.info("Config saved")