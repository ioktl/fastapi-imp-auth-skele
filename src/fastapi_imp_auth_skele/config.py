import os
from configparser import ConfigParser


def _load_config():
    if not "CONFIG" in os.environ:
        raise Exception("environment variable with config path (CONFIG) not found")
    cfg = ConfigParser()
    cfg.read(os.environ["CONFIG"])
    return cfg["DEFAULT"]


config = _load_config()
