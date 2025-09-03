import os
from enum import Enum

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
    LOCAL = os.getenv("LOCAL", None)


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
    IBM_LOG_SOURCES_GROUPS_ENDPOINT = (
        "api/config/event_sources/log_source_management/log_source_groups"
    )
    IBM_OFFENSES_ENDPOINT = "api/siem/offenses"
    IBM_EPS_ENDPOINT = "api/ariel/searches"
    AQL_QUERY_FOR_ADMIN_DASHBOARD = "SELECT DOMAINNAME(domainid)   AS Customer, SUM(eventcount) / ( (MAX(endtime) - MIN(starttime)) / 1000 ) AS EPS FROM events GROUP BY domainid ORDER BY EPS DESC LAST 1 HOURS"
    AQL_QUERY_FOR_SUSPICIOUS_EVENTS = "SELECT qidname(qid) as event_name, COUNT(*) as event_count FROM events WHERE domainid = {domain_id} AND (LOWER(categoryname(category)) LIKE '%suspicious%' OR LOWER(qidname(qid)) LIKE '%suspicious%' OR LOWER(qidname(qid)) LIKE '%leakage%' OR LOWER(qidname(qid)) LIKE '%unauthorized%') GROUP BY qid ORDER BY event_count DESC LIMIT 10 START PARSEDATETIME('{start_time}') STOP PARSEDATETIME('{end_time}')"
    AQL_QUERY_FOR_RECON_EVENTS = "SELECT COUNT(*) as total_recon_events FROM events WHERE domainid = {domain_id} AND (LOWER(categoryname(category)) LIKE '%reconnaissance%' OR LOWER(qidname(qid)) LIKE '%reconnaissance%' OR LOWER(qidname(qid)) LIKE '%recon%' OR LOWER(qidname(qid)) LIKE '%scan%') START PARSEDATETIME('{start_time}') STOP PARSEDATETIME('{end_time}')"
    AQL_QUERY_FOR_CORRELATED_EVENTS = "SELECT COUNT(*) AS correlated_events_count FROM events WHERE domainid = {domain_id} AND creeventlist IS NOT NULL START PARSEDATETIME('{start_time}') STOP PARSEDATETIME('{end_time}')"
    AQL_QUERY_FOR_WEEKLY_CORRELATED_EVENTS = """
    SELECT
        DATEFORMAT(starttime,'yyyy-ww') AS week,
        COUNT(*) AS weekly_count
    FROM events
    WHERE domainid = {domain_id}
        AND creeventlist IS NOT NULL
    GROUP BY DATEFORMAT(starttime,'yyyy-ww')
    ORDER BY week DESC
    LIMIT 4
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    # AQL_QUERY_FOR_SUSPICIOUS_EVENTS = """
    # SELECT COUNT(*) AS total_suspicious_events
    # FROM events
    # WHERE domainid = {domain_id}
    # AND highLevelCategory = 7000
    # START PARSEDATETIME('{start_time}')
    # STOP PARSEDATETIME('{end_time}')
    # """
    AQL_QUERY_FOR_DOS_EVENTS = """
    SELECT COUNT(*) AS total_dos_events
    FROM events
    WHERE domainid = {domain_id}
    AND highLevelCategory = 2000
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_TOP_DOS_EVENTS = """
    SELECT
        qidname(qid) AS event_name,
        COUNT(*) AS event_count
    FROM events
    WHERE domainid = {domain_id}
        AND highLevelCategory = 2000
    GROUP BY qid
    ORDER BY event_count DESC
    LIMIT 10
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """

    AQL_QUERY_FOR_DAILY_EVENTS = """
    SELECT
        DATEFORMAT(starttime,'yyyy-MM-dd') AS date,
        COUNT(*) AS daily_count
    FROM events
    WHERE domainid = {domain_id}
        AND creeventlist IS NOT NULL
    GROUP BY DATEFORMAT(starttime,'yyyy-MM-dd')
    ORDER BY date
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_TOP_ALERT_EVENTS = """
    SELECT
        rulename(creeventlist) AS alert_name,
        COUNT(*) AS event_count
    FROM events
    WHERE domainid = {domain_id}
        AND creeventlist IS NOT NULL
    GROUP BY creeventlist
    ORDER BY event_count DESC
    LIMIT 10
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_DAILY_CLOSURE_REASONS = """
    SELECT
        DATEFORMAT(starttime,'yyyy-MM-dd') AS date,
        CASE
            WHEN magnitude <= 3 THEN 'False Positive - Tuned'
            WHEN magnitude BETWEEN 4 AND 6 THEN 'True Positive - Existing Incident Updated'
            WHEN magnitude >= 7 THEN 'False Positive - Fine tuning not required'
            ELSE 'True Positive - Incident Raised'
        END AS closure_reason,
        COUNT(*) AS reason_count
    FROM events
    WHERE domainid = {domain_id}
        AND creeventlist IS NOT NULL
    GROUP BY DATEFORMAT(starttime,'yyyy-MM-dd'),
        CASE
            WHEN magnitude <= 3 THEN 'False Positive - Tuned'
            WHEN magnitude BETWEEN 4 AND 6 THEN 'True Positive - Existing Incident Updated'
            WHEN magnitude >= 7 THEN 'False Positive - Fine tuning not required'
            ELSE 'True Positive - Incident Raised'
        END
    ORDER BY date, closure_reason
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_MONTHLY_AVG_EPS = """
    SELECT
        SUM(eventcount) / (30 * 24 * 60 * 60) AS monthly_avg_eps
    FROM events
    WHERE domainid = {domain_id}
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_LAST_MONTH_AVG_EPS = """
    SELECT
        SUM(eventcount) / (31 * 24 * 60 * 60) AS last_month_avg_eps
    FROM events
    WHERE domainid = {domain_id}
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_WEEKLY_AVG_EPS = """
    SELECT
        DATEFORMAT(starttime,'yyyy-ww') AS week,
        DATEFORMAT(MIN(starttime),'dd-MMM') AS week_start,
        SUM(eventcount) / (7 * 24 * 60 * 60) AS weekly_avg_eps
    FROM events
    WHERE domainid = {domain_id}
    GROUP BY DATEFORMAT(starttime,'yyyy-ww')
    ORDER BY week
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_TOTAL_TRAFFIC = """
    SELECT
        SUM(eventcount) AS total_traffic
    FROM events
    WHERE domainid = {domain_id}
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_DESTINATION_ADDRESS_COUNTS = """
    SELECT
        destinationaddress,
        COUNT(*) AS address_count
    FROM events
    WHERE domainid = {domain_id}
    GROUP BY destinationaddress
    ORDER BY address_count DESC
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_TOP_DESTINATION_CONNECTION_COUNTS = """
    SELECT
        destinationaddress,
        SUM(eventcount) AS connection_count
    FROM events
    WHERE domainid = {domain_id}
    GROUP BY destinationaddress
    ORDER BY connection_count DESC

    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_DAILY_EVENT_COUNTS = """
    SELECT
        DATEFORMAT(starttime,'yyyy-MM-dd') AS full_date,
        SUM(eventcount) AS daily_count
    FROM events
    WHERE domainid = {domain_id}
    GROUP BY DATEFORMAT(starttime,'yyyy-MM-dd')
    ORDER BY full_date
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """
    AQL_QUERY_FOR_SUCCESSFUL_LOGONS = """
    SELECT
        username,
        qidname(qid) AS logon_type,
        sourceip,
        LOGSOURCENAME(logsourceid) AS log_source,
        COUNT(*) AS event_count
    FROM events
    WHERE domainid = {domain_id}
        AND highLevelCategory = 3000
        AND username IS NOT NULL
        AND username != 'N/A'
        AND LOWER(qidname(qid)) LIKE '%success%'
    GROUP BY username, qid, sourceip, logsourceid
    ORDER BY event_count DESC
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """

    AQL_QUERY_FOR_REMOTE_USERS_COUNT = """
    SELECT UNIQUECOUNT(username) AS total_remote_users
    FROM events
    WHERE domainid = {domain_id}
     AND (LOWER(rulename(creeventlist)) LIKE '%vpn%'
         OR LOWER(rulename(creeventlist)) LIKE '%remote%'
         OR LOWER(rulename(creeventlist)) LIKE '%ssh%')
     AND username IS NOT NULL
    START PARSEDATETIME('{start_time}')
    STOP PARSEDATETIME('{end_time}')
    """

    AQL_QUERY_FOR_GEOLOCATION = "SELECT sourceip, GEO::LOOKUP(sourceip, 'geo_json') AS geo FROM events group by sourceip"
    AQL_EPS_UPDATED_QUERY = """SELECT DOMAINNAME(domainid) AS 'client',"Hostname" AS 'Hostname',MAX("Value") AS 'Peak EPS', AVG("Value") AS 'Average EPS',DATEFORMAT(endtime,'YYYY-MM-dd hh:mm:ss') AS 'Time',NOW() AS 'Current Timestamp (ms)' from events where ( "Metric ID"='EventRate' AND "deviceType"='368' ) GROUP BY "Hostname" """

    # adding two more queries given by Mutahir
    AQL_QUERY_FOR_DOMAIN_EVENTS_AEP = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid) AS 'DOMAIN_NAME', categoryname(category - category % 1000) AS 'High Level Category', categoryname(category) AS 'Event Name', COUNT(*) AS 'Count' from events where (category - category % 1000)='5000' GROUP BY (category - category % 1000), category order by "Count" desc last 1 DAYS"""

    AQL_QUERY_FOR_DOMAIN_WISE_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid) AS 'DOMAIN_NAME', logsourcename(logSourceId) AS 'Log Source', COUNT(*) AS 'Count' from events where ( (logSourceId<'63') or (logSourceId>'63' and logSourceId<'69') or (logSourceId>'69' and logSourceId<'117') or (logSourceId>'117' and logSourceId<'18876') or (logSourceId>'18876') AND ("domainId"='5') or ("domainId"='6') or ("domainId"='10') AND ('Log Source'NOT ILIKE'%wincollect%') ) AND "Log Source" <> 'Health Metrics-2 :: MEYLVQRCON01' GROUP BY logSourceId order by "Count" desc last 24 hours"""

    AQL_QUERY_FOR_SENITIVE_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid),"sourceIP" AS 'Source IP', "destinationIP" AS 'Destination IP', "destinationPort" AS 'Destination Port', "destinationGeographicLocation" AS 'Destination Geographic Country/Region', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ( ( (category='4002') or (category='4012') AND ("destinationIP"<'10.0.0.0') or ("destinationIP">'10.255.255.255' and "destinationIP"<'172.16.0.0') or ("destinationIP">'172.31.255.255' and "destinationIP"<'192.168.0.0') or ("destinationIP">'192.168.255.255') ) AND ("deviceType"='20') or ("deviceType"='73') or ("deviceType"='194') or ("deviceType"='206') or ("deviceType"='270') ) AND ("sourceIP">='10.0.0.0' and "sourceIP"<='10.255.255.255') or ("sourceIP">='172.16.0.0' and "sourceIP"<='172.31.255.255') or ("sourceIP">='192.168.0.0' and "sourceIP"<='192.168.255.255') ) AND "Destination Port" = 21 or "Destination Port" = 22 OR "Destination Port" = 135 OR "Destination Port" = 137 OR "Destination Port" = 3389 OR "Destination Port" = 445 GROUP BY "sourceIP", "destinationIP", "destinationPort", "destinationGeographicLocation" order by "Event Count (Sum)" desc LIMIT 50 last 24 hours"""

    AQL_QUERY_FOR_CORRELATED_EVENTS_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid) as 'DOMAIN NAME',QIDNAME(qid) AS 'Event Name', MAX("magnitude") AS 'Magnitude (Maximum)', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where (logSourceId='63') or (logSourceId='117') or (logSourceId='18876') GROUP BY qid order by "Event Count (Sum)" desc last 24 hours"""

    AQL_QUERY_FOR_AEP_ENTRA_FAILURES_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid) as 'DOMAIN NAME',"EntraID Identity" AS "User" ,categoryname(category) AS 'Low Level Category', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ( ( ( ("Entra_id Category"='NonInteractiveUserSignInLogs') or ("Entra_id Category"='SignInLogs') AND (category<'3012') or (category>'3012' and category<'3115') or (category>'3115') ) AND logSourceId='19840' ) AND "domainId"='10' ) AND (category - category % 1000)='3000' ) GROUP BY "user" order by "Event Count (Sum)" desc limit 10 last 1 DAYS"""

    AQL_QUERY_FOR_ALLOWED_OUTBOUND_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime', DOMAINNAME(domainid),"sourceIP" AS 'Source IP', "destinationIP" AS 'Destination IP', "destinationPort" AS 'Destination Port', "destinationGeographicLocation" AS 'Destination Geographic Country/Region', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where ( ( ( (category='4002') or (category='4012') AND ("destinationIP"<'10.0.0.0') or ("destinationIP">'10.255.255.255' and "destinationIP"<'172.16.0.0') or ("destinationIP">'172.31.255.255' and "destinationIP"<'192.168.0.0') or ("destinationIP">'192.168.255.255') ) AND ("deviceType"='20') or ("deviceType"='73') or ("deviceType"='194') or ("deviceType"='206') or ("deviceType"='270') ) AND ("sourceIP">='10.0.0.0' and "sourceIP"<='10.255.255.255') or ("sourceIP">='172.16.0.0' and "sourceIP"<='172.31.255.255') or ("sourceIP">='192.168.0.0' and "sourceIP"<='192.168.255.255') ) GROUP BY "sourceIP", "destinationIP", "destinationPort", "destinationGeographicLocation" order by "Event Count (Sum)" desc LIMIT 50 last 24 hours"""

    AQL_QUERY_FOR_ALLOWED_INBOUND_DATA = """SELECT DATEFORMAT(starttime,'YYYY-MM-dd hh:mm') as 'startTime',DOMAINNAME(domainid),"sourceIP" AS 'Source IP', "destinationIP" AS 'Destination IP', "destinationPort" AS 'Destination Port', UniqueCount("destinationGeographicLocation") AS 'Destination Geographic Country/Region (Unique Count)', SUM("eventCount") AS 'Event Count (Sum)', COUNT(*) AS 'Count' from events where (( ( ( (category='4002') or (category='4012') or (category='4014') AND ("destinationIP">='10.0.0.0' and "destinationIP"<='10.255.255.255') or ("destinationIP">='172.16.0.0' and "destinationIP"<='172.31.255.255') or ("destinationIP">='192.168.0.0' and "destinationIP"<='192.168.255.255') ) AND ("deviceType"='20') or ("deviceType"='73') or ("deviceType"='183') or ("deviceType"='206') or ("deviceType"='273') ) AND ("sourceIP"<'10.0.0.0') or ("sourceIP">'10.255.255.255' and "sourceIP"<'172.16.0.0') or ("sourceIP">'172.31.255.255' and "sourceIP"<'192.168.0.0') or ("sourceIP">'192.168.255.255') ) AND "Source IP" <> '127.0.0.1') AND "Destination IP" <> '0.0.0.0' GROUP BY "sourceIP", "destinationIP", "destinationPort" order by "Count" desc LIMIT 50 last 24 hours"""


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
    NOTES_ENDPOINT = "investigation"
    BATCH_SIZE = 10000
    EXPECTED_FIELDS = [
        "Rule Description",
        "Description",
        "Analysis",
        "Incident Analysis",
        "Payload",
        "Payloads",
        "Impact",
        "Impacts",
        "Recommendation",
        "Recommendations",
    ]


class AdminWebsocketConstants:
    SYSTEM_METRICS_GROUP_NAME = "system_metrics_group"


class PaginationConstants:
    PAGE_SIZE = 10


class LDAPConstants:
    LDAP_PORT = os.getenv("LDAP_PORT", None)
    ADMIN_BASE_DN = (
        "OU=ICT Managed Services Platform,DC=mscloudinfra,DC=com"  # OU=Wipro_CSOC,
    )
    ADMIN_BIND_DOMAIN = os.getenv("ADMIN_BIND_DOMAIN", None)
    ADMIN_LDAP_SERVERS = os.getenv("ADMIN_LDAP_SERVERS", None)
    LDAP_BIND_USER = os.getenv("LDAP_BIND_USER", None)
    LDAP_BIND_PASSWORD = os.getenv("LDAP_BIND_PASSWORD", None)

    CUSTOMER_BASE_DN = "OU=CloudU_Customers,OU=Azure-Cloud-Sync,OU=ICT_Cloud_Operations_Teams,DC=cloudu,DC=local"
    CUSTOMER_BIND_DOMAIN = os.getenv("CUSTOMER_BIND_DOMAIN", None)
    CUSTOMER_LDAP_SERVERS = os.getenv("CUSTOMER_LDAP_SERVERS", None)

    if LDAP_PORT is None:
        logger.warning("LDAP port is not set...")
        raise ValueError("LDAP port is not set...")

    if ADMIN_BIND_DOMAIN is None:
        logger.warning("ADMIN LDAP bind domain is not set...")
        raise ValueError("ADMIN LDAP bind domain is not set...")

    if LDAP_BIND_USER is None:
        logger.warning("LDAP bind user is not set...")
        raise ValueError("LDAP bind user is not set...")

    if LDAP_BIND_PASSWORD is None:
        logger.warning("LDAP bind password is not set...")
        raise ValueError("LDAP bind password is not set...")

    if ADMIN_LDAP_SERVERS is None:
        logger.warning("ADMIN LDAP servers are not set...")
        raise ValueError("ADMIN LDAP servers are not set...")

    if CUSTOMER_BIND_DOMAIN is None:
        logger.warning("CUSTOMER LDAP bind domain is not set...")
        raise ValueError("CUSTOMER LDAP bind domain is not set...")

    if CUSTOMER_LDAP_SERVERS is None:
        logger.warning("LDAP servers are not set...")
        raise ValueError("LDAP servers are not set...")

    ADMIN_LDAP_SERVERS = ADMIN_LDAP_SERVERS.split(",")
    CUSTOMER_LDAP_SERVERS = CUSTOMER_LDAP_SERVERS.split(",")


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


class FilterType(Enum):
    TODAY = 1
    WEEK = 2
    MONTH = 3
    # YEAR = 4
    # QUARTER = 5
    # LAST_6_MONTHS = 6  # Represents "Last 6 months"
    # LAST_3_WEEKS = 7  # Represents "Last 3 weeks"
    # LAST_MONTH = 8  # Repre
    CUSTOM_RANGE = 9


SEVERITY_LABELS = {0: "Unknown", 1: "Low", 2: "Medium", 3: "High", 4: "Critical"}


class APIConstants:
    API_VERSION = "v1.0.0"
    API_NAME = "duSOC Portal Backend API"
    API_DESCRIPTION = "Backend API for duSOC Portal application"
