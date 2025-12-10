from mcp.server.fastmcp import FastMCP
import requests
import json
import binascii
import traceback
from dotenv import load_dotenv
import os

load_dotenv()
API_ID = os.getenv("API_ID")
API_KEY = os.getenv("API_KEY")

mcp = FastMCP("AI-SOC-Agent")


def get_headers():
    return {"X-HoneyDb-ApiId": API_ID, "X-HoneyDb-ApiKey": API_KEY}


def safe_api_request(url: str):
    try:
        response = requests.get(url, headers=get_headers(), timeout=10)
        if response.status_code != 200:
            return False, f"API Error {response.status_code}: {response.text}"
        return True, response.json()
    except Exception:
        return False, traceback.format_exc()


@mcp.tool()
def find_ips_exploiting_cve(cve_id: str) -> str:
    """
    Mencari daftar IP Address yang terdeteksi mencoba mengeksploitasi CVE tertentu, contoh cve_id: 'CVE-2025-5777'
    Parameter   : CVE ID (Common Vulnerabilities and Exposures)
    Return      : list IP & tanggal
    """

    url = f"https://honeydb.io/api/cve/{cve_id}"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal mencari CVE {cve_id}: {data}"

    if not data:
        return f"Tidak ditemukan aktivitas untuk {cve_id}."

    return json.dumps(data, indent=2)


@mcp.tool()
def check_cve_history_by_ip(ip_address: str) -> str:
    """
    Melihat riwayat CVE apa saja yang pernah dicoba dieksploitasi oleh satu IP tertentu.
    Parameter   : IP
    Return      : List CVE & tanggal
    """

    url = f"https://honeydb.io/api/cve/ip/{ip_address}"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal mengambil history CVE untuk IP {ip_address}: {data}"

    return json.dumps(data, indent=2)


@mcp.tool()
def get_monthly_payload_history(year: str, month: str, nsample: int = 10) -> str:
    """
    Mengambil riwayat payload (script/file berbahaya) yang ditangkap pada bulan tertentu.
    Parameter   : year (misal '2024'), month (misal '04')
    Return      : List tanggal, service, attribute, hash, dan value.
    """

    url = f"https://honeydb.io/api/payload-history/{year}/{month}"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal mengambil payload history: {data}"

    sample = data[:nsample] if isinstance(data, list) else data
    return json.dumps(sample, indent=2)


@mcp.tool()
def analyze_payload_hash(payload_hash: str) -> str:
    """
    Menganalisis detail payload berdasarkan Hash-nya. Gunakan ini jika menemukan hash dari 'get_monthly_payload_history'.
    Ini akan menampilkan konten payload (biasanya hex) dan perintah yang dijalankan.
    Parameter   : Hash payload
    Return      : Detail payload
    """

    url = f"https://honeydb.io/api/payload-history/{payload_hash}"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal menganalisis hash {payload_hash}: {data}"

    return json.dumps(data, indent=2)


@mcp.tool()
def scan_threat_feeds(ip_address: str) -> str:
    """
    Melakukan scan terhadap satu IP di berbagai database Threat Intelligence sekaligus.
    Mengecek: Tor Exit Node, ThreatFox (Malware), Project Honeypot, Emerging Threats, dan Bogon.
    Parameter   : IP
    Return      : List threat intelligence status
    """
    results = {"target_ip": ip_address, "scan_results": {}}

    checks = {
        "Tor_Exit_Node": f"https://honeydb.io/api/ipinfo/tor/{ip_address}",
        "ThreatFox_Malware": f"https://honeydb.io/api/ipinfo/threatfox/{ip_address}",
        "Project_Honeypot": f"https://honeydb.io/api/ipinfo/project-honeypot/{ip_address}",
        "Emerging_Threats": f"https://honeydb.io/api/ipinfo/et-compromised/{ip_address}",
        "Bogon_IP": f"https://honeydb.io/api/ipinfo/bogon/{ip_address}",
    }

    for check_name, url in checks.items():
        success, data = safe_api_request(url)
        if success:
            results["scan_results"][check_name] = data
        else:
            results["scan_results"][check_name] = "Error/Not Found"

    return json.dumps(results, indent=2)


@mcp.tool()
def get_bad_hosts(limit: int = 10) -> str:
    """
    Mengambil daftar 'Bad Hosts' (IP berbahaya) yang terdeteksi dalam 24 jam terakhir
    Parameter   : Limit (defailt 10)
    Return      : List host sample teratas (count tertinggi)
    """
    # Endpoint valid dari PDF Halaman 1 [cite: 43]
    url = "https://honeydb.io/api/bad-hosts"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal mengambil Bad Hosts: {data}"

    try:
        sorted_data = sorted(data, key=lambda x: int(x.get("count", 0)), reverse=True)[
            :limit
        ]
        return json.dumps(sorted_data, indent=2)
    except Exception as e:
        return f"Error parsing data: {str(e)}"


@mcp.tool()
def get_active_services() -> str:
    """
    Melihat services/protokol jaringan yang diemulasikan honeypot dan sedang aktif diserang.
    """

    url = "https://honeydb.io/api/services"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal mengambil Services: {data}"

    return json.dumps(data, indent=2)


@mcp.tool()
def check_ip_details(ip_address: str) -> str:
    """
    Melakukan pengecekan mendalam pada satu IP Address.
    Menggabungkan Info Jaringan (ASN/Geo) dan Info Threat (Tor/Bogon/List).

    """
    report = {"target_ip": ip_address}

    # 1. Cek Geolocation & ASN
    url_netinfo = f"https://honeydb.io/api/netinfo/lookup/{ip_address}"
    success_net, data_net = safe_api_request(url_netinfo)
    if success_net:
        report["network_info"] = data_net

    # 2. Cek apakah IP masuk blacklist
    url_ipinfo = f"https://honeydb.io/api/ipinfo/{ip_address}"
    success_info, data_info = safe_api_request(url_ipinfo)
    if success_info:
        report["threat_lists"] = data_info

    return json.dumps(report, indent=2)


@mcp.tool()
def check_internet_scanner(ip_address: str) -> str:
    """
    Mendeteksi apakah IP tersebut adalah scanner internet dikenal (Shodan/Censys)
    """

    url = f"https://honeydb.io/api/internet-scanner/info/{ip_address}"

    success, data = safe_api_request(url)
    if not success:
        return f"Gagal cek scanner: {data}"

    return json.dumps(data, indent=2)


if __name__ == "__main__":
    mcp.run()
