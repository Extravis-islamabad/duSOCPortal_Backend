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


class EnvConstants:
    ENV = os.getenv("ENV", None)


class SSLConstants:
    if EnvConstants.ENV:
        VERIFY = True
    else:
        VERIFY = False
    TIMEOUT = 40


class AllowedOriginsConstants:
    LOCAL_URL = os.getenv("LOCAL_URL", None)
    DEV_URL = os.getenv("DEV_URL", None)

    if LOCAL_URL is None or DEV_URL is None:
        logger.warning("Allowed origins are not set...")
        raise ValueError("Allowed origins are not set...")
    ALLOWED_ORIGINS = [
        LOCAL_URL,
        DEV_URL,
        "http://192.168.10.26",
        "http://localhost:3000",
    ]


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


class RabbitmqConstants:
    RABBITMQ_HOST = os.getenv("RABBITMQ_HOST", None)
    RABBITMQ_AMQP_PORT = os.getenv("RABBITMQ_AMQP_PORT", None)
    RABBITMQ_MUI_PORT = os.getenv("RABBITMQ_MUI_PORT", None)
    RABBITMQ_DEFAULT_USER = os.getenv("RABBITMQ_DEFAULT_USER", None)
    RABBITMQ_DEFAULT_PASS = os.getenv("RABBITMQ_DEFAULT_PASS", None)

    if (
        RABBITMQ_HOST is None
        or RABBITMQ_AMQP_PORT is None
        or RABBITMQ_MUI_PORT is None
        or RABBITMQ_DEFAULT_USER is None
        or RABBITMQ_DEFAULT_PASS is None
    ):
        logger.warning("Rabbitmq credentials are not set...")
        raise ValueError("Rabbitmq credentials are not set...")


class IBMQradarConstants:
    IBM_ABOUT_ENDPOINT = "api/system/about"
    IBM_TENANT_ENDPOINT = "api/config/access/tenant_management/tenants"
    IBM_DOMAIN_ENDPOINT = "api/config/domain_management/domains"
    IBM_EVENT_COLLECTOR_ENDPOINT = "api/config/event_sources/event_collectors"
    IBM_EVENT_LOGS_ENDPOINT = (
        "api/config/event_sources/log_source_management/log_sources"
    )
    IBM_LOG_SOURCES_TYPES_ENDPOINT = (
        "api/config/event_sources/log_source_management/log_source_types"
    )
    IBM_OFFENSES_ENDPOINT = "api/siem/offenses"
    IBM_EPS_ENDPOINT = "api/ariel/searches"


class ITSMConstants:
    ITSM_START_INDEX = 1
    ITSM_ROW_COUNT = 1000
    STATUS_CODE = 2000
    SUCCESS = "success"
    ITSM_ACCOUNTS_ENDPOINT = "api/v3/accounts"
    ITSM_REQUESTS_ENDPOINT = "api/v3/requests"


class CortexSOARConstants:
    TENANT_ENDPOINT = "accounts"
    INCIDENT_ENDPOINT = "incidents/search"


class AdminWebsocketConstants:
    SYSTEM_METRICS_GROUP_NAME = "system_metrics_group"


class PaginationConstants:
    PAGE_SIZE = 10


class LDAPConstants:
    LDAP_PORT = 389
    BASE_DN = "OU=Wipro_CSOC,OU=ICT Managed Services Platform,DC=mscloudinfra,DC=com"
    BIND_DOMAIN = "mscloudinfra.com"
    LDAP_SERVERS = ["10.225.128.135", "10.225.128.136"]
    LDAP_BIND_USER = "svc.soc.portal"  # nosec
    LDAP_BIND_PASSWORD = "SeonRx##0@55555"  # nosec


class CywareConstants:
    EXPIRATION_MARGIN_TIME = 300
    LIST_ALERT_ENDPOINT = "csap/v1/list_alert/"
    TAGS_ENDPOINT = "api/csap/v1/tag/"
    GROUPS_ENDPOINT = "api/csap/v1/list_recipient_group/"
    CUSTOM_FIELDS_ENDPOINT = "api/csap/v1/list_additional_fields/"
    CATEGORIES_ENDPOINT = "api/csap/v1/list_category/"
    ALERT_DETAIL_ENDPOINT = "api/csap/v1/get_alert_detail/"


class EncryptedKeyConstants:
    ENCRYPTED_KEY = os.getenv("ENCRYPTED_KEY", None)
    if ENCRYPTED_KEY is None:
        logger.warning("Encrypted key is not set...")
        raise ValueError("Encrypted key is not set...")
