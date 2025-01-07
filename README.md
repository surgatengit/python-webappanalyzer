# python-webappanalyzer

```bash
git clone https://github.com/surgatengit/python-webappanalyzer && cd cd python-webappanalyzer/
pip install -r requirements.txt
```

python implementation of the webappanalyzer detectors.

```python
import json

import requests
from requests import Response

from webappanalyzer.webappanalyzer import WebAppAnalyzer
from webappanalyzer.web_page import WebPage

if __name__ == '__main__':
    response: Response = requests.get("https://enthec.com/", headers={"User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0"})
    page: WebPage = WebPage.new_from_response(response)
    print(json.dumps(WebAppAnalyzer().analyze(page), indent=2))

```
