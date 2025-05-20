import requests
from bs4 import BeautifulSoup

def fetch_bugcrowd_updates():
    """Retrieve latest Bugcrowd blog posts."""
    url = "https://www.bugcrowd.com/blog/"
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0"})
    
    if response.status_code == 200:
        soup = BeautifulSoup(response.content, "html.parser")
        articles = soup.find_all("h2", class_="post-title")  # Adjust selector if needed
        return [(article.text, article.a["href"]) for article in articles[:5]]
    else:
        return f"❌ ERROR: Unable to fetch Bugcrowd blog - HTTP {response.status_code}"

print(fetch_bugcrowd_updates())
