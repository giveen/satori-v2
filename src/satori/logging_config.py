import logging

def setup_logging(level: str = "INFO"):
    levelno = getattr(logging, level.upper(), logging.INFO)
    fmt = "%(asctime)s %(levelname)s [%(name)s] %(message)s"
    logging.basicConfig(level=levelno, format=fmt)
