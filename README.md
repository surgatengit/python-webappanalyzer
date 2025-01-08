# python-webappanalyzer

In the folder of your choice, copy, paste and run.
```bash
git clone https://github.com/surgatengit/python-webappanalyzer && cd python-webappanalyzer && pip install -r requirements.txt && echo "Ready, Use: python scanwebtech.py <URL>"
```
Use
```bash
python scanwebtechs.py <URL>
```

For CTF you can use jq like this
```
python scanwebtech.py https://fwhibbit.es | jq -r '.[] | "\((.categories // ["No categories"])) \(.tech)\(if .version then " " + .version else "" end)"'

["JavaScript libraries"] jQuery
["JavaScript libraries"] jQuery Migrate 3.4.1
["Cookie compliance","WordPress plugins"] Cookie Notice 2.4.11
["CMS","Blogs"] WordPress
["Web servers"] Apache HTTP Server
["WordPress themes"] aThemes Sydney
["Programming languages"] PHP 8.1.31
["Performance"] Priority Hints
["Miscellaneous"] RSS
["No categories"] MySQL
```
forked from https://github.com/enthec/python-webappanalyzer with changes for CTFs.

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
