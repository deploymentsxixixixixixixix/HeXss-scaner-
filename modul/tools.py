import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin

def find_images_on_page(url):
    """
    Mencari dan mencetak semua URL gambar (JPG, PNG, GIF) di halaman web yang diberikan.
    """
    try:
        response = requests.get(url)
        response.raise_for_status() # Akan memunculkan HTTPError untuk status kode 4xx/5xx
    except requests.exceptions.RequestException as e:
        print(f"Error mengakses URL {url}: {e}")
        return

    soup = BeautifulSoup(response.text, 'html.parser')
    image_tags = soup.find_all('img')

    found_images = []
    for img in image_tags:
        src = img.get('src')
        if src:
            # Menggabungkan URL relatif dengan URL dasar
            absolute_src = urljoin(url, src)
            
            # Cek apakah ekstensi file adalah JPG, PNG, atau GIF
            if absolute_src.lower().endswith(('.jpg', '.jpeg', '.png', '.gif')):
                found_images.append(absolute_src)
    
    if found_images:
        print(f"\nDitemukan gambar di {url}:")
        for image_url in found_images:
            print(f"- {image_url}")
    else:
        print(f"\nTidak ditemukan gambar (JPG/PNG/GIF) di {url}.")

if __name__ == "__main__":
    # Ganti dengan URL website Anda sendiri atau yang Anda punya izinnya.
    # JANGAN gunakan URL website orang lain tanpa izin!
    target_url = input("Masukkan URL website yang ingin Anda pindai (misalnya, https://contoh.com): ")
    
    if not target_url.startswith(('http://', 'https://')):
        print("URL tidak valid. Harap masukkan URL lengkap dengan 'http://' atau 'https://'.")
    else:
        find_images_on_page(target_url)