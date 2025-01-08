import json
import requests
from webappanalyzer.webappanalyzer import WebAppAnalyzer
from webappanalyzer.web_page import WebPage
import sys
import warnings

warnings.filterwarnings("ignore", category=FutureWarning)

def analyze_website(url):
    response = requests.get(url, headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"})
    page = WebPage.new_from_response(response)
    print(json.dumps(WebAppAnalyzer().analyze(page), indent=2))

if __name__ == '__main__':
    if len(sys.argv) != 2:
        print("Usage: python scanwebtechs.py <url>")
        sys.exit(1)
    url = sys.argv[1]
    analyze_website(url)
