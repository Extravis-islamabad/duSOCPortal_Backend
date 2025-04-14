import os

from dotenv import load_dotenv
from loguru import logger

load_dotenv()


class DatabaseConstants:
    DATABASE_NAME = os.getenv("DB_NAME", None)
    DATABASE_USER = os.getenv("DB_USER", None)
    DATABASE_PASSWORD = os.getenv("DB_PASSWORD", None)
    DATABASE_HOST = os.getenv("DB_HOST", None)
    DATABASE_PORT = os.getenv("DB_PORT", None)
    if DATABASE_PORT is not None:
        DATABASE_PORT = int(DATABASE_PORT)
    DATABASE_ENGINE = os.getenv("DB_ENGINE", None)

    if (
        DATABASE_NAME is None
        or DATABASE_USER is None
        or DATABASE_PASSWORD is None
        or DATABASE_HOST is None
        or DATABASE_PORT is None
        or DATABASE_ENGINE is None
    ):
        logger.warning("Database credentials are not set...")
        raise ValueError("Database credentials are not set...")
