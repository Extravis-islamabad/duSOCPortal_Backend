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


class DjangoConstants:
    SECRET_KEY = os.getenv("SECRET_KEY", None)
    if SECRET_KEY is None:
        logger.warning("Secret key is not set...")
        raise ValueError("Secret key is not set...")


class AllowedOriginsConstants:
    LOCAL_URL = os.getenv("LOCAL_URL", None)
    DEV_URL = os.getenv("DEV_URL", None)

    if LOCAL_URL is None or DEV_URL is None:
        logger.warning("Allowed origins are not set...")
        raise ValueError("Allowed origins are not set...")
    ALLOWED_ORIGINS = [LOCAL_URL, DEV_URL, "http://localhost:3000"]


class AllowedHostsConstants:
    LOCAL_HOST = os.getenv("LOCAL_HOST", None)
    DEV_HOST = os.getenv("DEV_HOST", None)

    if LOCAL_HOST is None or DEV_HOST is None:
        logger.warning("Allowed hosts are not set...")
        raise ValueError("Allowed hosts are not set...")

    ALLOWED_HOSTS = [LOCAL_HOST, DEV_HOST]


class RedisConstants:
    REDIS_HOST = os.getenv("REDIS_HOST", None)
    REDIS_PORT = os.getenv("REDIS_PORT", None)

    if REDIS_HOST is None or REDIS_PORT is None:
        logger.warning("Redis credentials are not set...")
        raise ValueError("Redis credentials are not set...")
