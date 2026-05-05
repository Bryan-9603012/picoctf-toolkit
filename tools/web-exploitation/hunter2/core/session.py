import requests


def build_session(cfg):
    s = requests.Session()

    # hunter config
    s._hunter_cfg = cfg

    # default headers
    s.headers.update({
        "User-Agent": "hunter/2.0 (authorized scanning)",
        "Accept": "*/*",
    })

    # proxy
    if getattr(cfg, "proxy", ""):
        s.proxies = {
            "http": cfg.proxy,
            "https": cfg.proxy,
        }

    # burp https intercept
    if getattr(cfg, "insecure", False):
        s.verify = False

    return s