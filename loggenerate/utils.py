import random
from datetime import datetime, timezone


PUBLIC_IPS = [
    "8.8.8.8", "8.8.4.4", "1.1.1.1", "1.0.0.1",
    "208.67.222.222", "9.9.9.9", "185.228.168.9",
    "104.16.132.229", "151.101.1.164", "172.217.18.142",
    "13.107.21.200", "52.96.184.100", "199.85.126.10",
    "31.13.72.36", "157.240.1.35", "104.244.42.1",
    "23.185.0.1", "76.76.19.19", "94.140.14.14",
]

COUNTRIES = [
    "United States", "United Kingdom", "Germany", "France", "Netherlands",
    "Canada", "Australia", "Japan", "China", "Russia", "Brazil", "India",
    "Singapore", "Sweden", "Switzerland", "South Korea", "Mexico",
    "Italy", "Spain", "Poland",
]

APPLICATIONS = [
    "ssl", "http", "dns", "smtp", "ssh", "ftp", "rdp",
    "office365", "msrpc", "netbios-ns", "dropbox",
    "youtube", "facebook", "instagram", "linkedin",
    "sharepoint", "teams", "zoom", "webex", "slack",
    "ntp", "snmp", "ldap", "kerberos", "quic",
    "splunk", "syslog", "sap", "oracle-database",
]

WELL_KNOWN_PORTS = [
    80, 443, 8080, 8443, 25, 587, 465, 21, 22, 53,
    3306, 5432, 1433, 3389, 6379, 27017, 5985, 5986,
]

USERS = [
    "alice", "bob", "charlie", "dave", "eve", "frank", "grace",
    "henry", "isabel", "jack", "kate", "liam", "mary", "nick",
    "olivia", "peter", "quinn", "rachel", "steve", "tina",
]


def rand_private_ip() -> str:
    return f"10.{random.randint(1, 254)}.{random.randint(0, 254)}.{random.randint(1, 254)}"


def rand_public_ip() -> str:
    return random.choice(PUBLIC_IPS)


def rand_ephemeral_port() -> int:
    return random.randint(49152, 65535)


def rand_well_known_port() -> int:
    return random.choice(WELL_KNOWN_PORTS)


def rand_country() -> str:
    return random.choice(COUNTRIES)


def rand_application() -> str:
    return random.choice(APPLICATIONS)


def rand_user(domain: str = "") -> str:
    user = random.choice(USERS)
    return f"{domain}\\{user}" if domain else user


def rand_bytes_pair() -> tuple:
    sent = random.randint(512, 1_048_576)
    recv = random.randint(512, 4_194_304)
    return sent, recv


def rand_packets_pair() -> tuple:
    sent = random.randint(5, 5000)
    recv = random.randint(5, 5000)
    return sent, recv


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def pan_timestamp(dt: datetime) -> str:
    return dt.strftime("%Y/%m/%d %H:%M:%S")


def fortinet_date(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%d")


def fortinet_time(dt: datetime) -> str:
    return dt.strftime("%H:%M:%S")
