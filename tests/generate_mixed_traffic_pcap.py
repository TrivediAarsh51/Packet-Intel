from scapy.all import *
import random
import os

# -----------------------------
# SAFE SIMULATED ENVIRONMENT
# -----------------------------

# Normal services / IPs
NORMAL_IPS = [
    "8.8.8.8", "1.1.1.1",
    "142.250.190.14",  # Google
    "151.101.1.140",   # GitHub
]

# Suspicious / fake domains
SUSPICIOUS_DOMAINS = [
    "srv-7x91-control.xyz",
    "cdn-sync-83k.biz",
    "node-telemetry-ax7.top",
]

# Malicious simulation IPs
MALICIOUS_IPS = [
    "185.220.101.45",
    "194.165.16.78",
    "45.142.212.100",
]

# -----------------------------
# PORT MAPPING (protocol simulation)
# -----------------------------

PORTS = {
    "http": 80,
    "https": 443,
    "dns": 53,
    "ssh": 22,
    "telnet": 23,
    "ftp": 21,
    "dhcp": 67,
}

# -----------------------------
# PAYLOADS (SIMULATED TRAFFIC)
# -----------------------------

HTTP_PAYLOADS = [
    b"GET /index.html HTTP/1.1",
    b"POST /login username=admin&password=123456",
    b"User-Agent: Mozilla/5.0",
]

HTTPS_PAYLOADS = [
    os.urandom(200),  # encrypted-like
    os.urandom(300),
]

DNS_PAYLOADS = [
    b"QUERY google.com",
    b"QUERY srv-7x91-control.xyz",
    b"QUERY login-security-check.example",
]

SSH_PAYLOADS = [
    b"SSH-2.0-OpenSSH_8.2",
    os.urandom(150),
]

TELNET_PAYLOADS = [
    b"login: admin",
    b"password: root123",
    b"GET SHELL",
]

FTP_PAYLOADS = [
    b"USER anonymous",
    b"PASS guest",
    b"RETR secret.txt",
]

DHCP_PAYLOADS = [
    b"DHCP DISCOVER",
    b"DHCP REQUEST",
    b"DHCP ACK",
]

EXFIL_PAYLOADS = [
    b"password=admin123",
    b"card=4111111111111111",
    b"ssn=123-45-6789",
    b"Authorization: Bearer faketoken1234567890",
]

# -----------------------------
# PACKET BUILDER
# -----------------------------

def build_packet(dst_ip, dport, payload, sport=None):
    if sport is None:
        sport = random.randint(1024, 65000)

    return IP(dst=dst_ip) / TCP(sport=sport, dport=dport) / Raw(load=payload)


# -----------------------------
# TRAFFIC GENERATORS
# -----------------------------

def generate_http():
    pkts = []
    for _ in range(20):
        ip = random.choice(NORMAL_IPS)
        payload = random.choice(HTTP_PAYLOADS)
        pkts.append(build_packet(ip, PORTS["http"], payload))
    return pkts


def generate_https():
    pkts = []
    for _ in range(20):
        ip = random.choice(NORMAL_IPS)
        payload = random.choice(HTTPS_PAYLOADS)
        pkts.append(build_packet(ip, PORTS["https"], payload))
    return pkts


def generate_dns():
    pkts = []
    for _ in range(20):
        ip = "8.8.8.8"
        domain = random.choice(SUSPICIOUS_DOMAINS + ["google.com", "github.com"])
        payload = f"DNS QUERY {domain}".encode()
        pkts.append(build_packet(ip, PORTS["dns"], payload))
    return pkts


def generate_ssh():
    pkts = []
    for _ in range(15):
        ip = random.choice(NORMAL_IPS)
        payload = random.choice(SSH_PAYLOADS)
        pkts.append(build_packet(ip, PORTS["ssh"], payload))
    return pkts


def generate_telnet():
    pkts = []
    for _ in range(10):
        ip = random.choice(MALICIOUS_IPS + NORMAL_IPS)
        payload = random.choice(TELNET_PAYLOADS)
        pkts.append(build_packet(ip, PORTS["telnet"], payload))
    return pkts


def generate_ftp():
    pkts = []
    for _ in range(10):
        ip = random.choice(NORMAL_IPS)
        payload = random.choice(FTP_PAYLOADS)
        pkts.append(build_packet(ip, PORTS["ftp"], payload))
    return pkts


def generate_dhcp():
    pkts = []
    for _ in range(10):
        ip = "255.255.255.255"
        payload = random.choice(DHCP_PAYLOADS)
        pkts.append(IP(dst=ip)/UDP(sport=68, dport=67)/Raw(load=payload))
    return pkts


def generate_malicious():
    pkts = []
    for _ in range(15):
        ip = random.choice(MALICIOUS_IPS)
        payload = random.choice(EXFIL_PAYLOADS)
        pkts.append(build_packet(ip, 80, payload))
    return pkts


def generate_high_entropy():
    pkts = []
    for _ in range(15):
        ip = "192.168.1." + str(random.randint(2, 250))
        payload = os.urandom(250)
        pkts.append(build_packet(ip, 443, payload))
    return pkts


# -----------------------------
# MAIN
# -----------------------------

def main():
    packets = []

    packets += generate_http()
    packets += generate_https()
    packets += generate_dns()
    packets += generate_ssh()
    packets += generate_telnet()
    packets += generate_ftp()
    packets += generate_dhcp()
    packets += generate_malicious()
    packets += generate_high_entropy()

    random.shuffle(packets)

    filename = "mixed_traffic.pcap"
    wrpcap(filename, packets)

    print("[+] PCAP generated:", filename)
    print("[+] Total packets:", len(packets))


if __name__ == "__main__":
    main()