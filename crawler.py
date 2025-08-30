import requests
from bs4 import BeautifulSoup
from urllib.parse import urljoin, urlparse
from collections import defaultdict

def crawl_website(base_url, max_depth=3):
    visited = set()
    urls = []
    forms = defaultdict(list)
    to_crawl = [(base_url, 0)]

    while to_crawl:
        url, depth = to_crawl.pop(0)
        if url in visited or depth > max_depth:
            continue
        visited.add(url)
        urls.append(url)
        try:
            response = requests.get(url)
            soup = BeautifulSoup(response.text, 'html.parser')
            # Find forms and inputs
            for form in soup.find_all('form'):
                form_details = {
                    'action': urljoin(url, form.attrs.get('action', '')),
                    'method': form.attrs.get('method', 'get').lower(),
                    'inputs': [{'name': i.attrs.get('name'), 'type': i.attrs.get('type', 'text')} for i in form.find_all('input')]
                }
                forms[url].append(form_details)
            # Find links
            for link in soup.find_all('a', href=True):
                next_url = urljoin(url, link['href'])
                if urlparse(next_url).netloc == urlparse(base_url).netloc:
                    to_crawl.append((next_url, depth + 1))
        except Exception:
            pass
    return urls, forms