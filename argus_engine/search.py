import requests
import secrets, re
import json
import os
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor, as_completed
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from urllib.parse import urlparse, parse_qs, unquote, quote_plus

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.7; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (X11; Linux i686; rv:137.0) Gecko/20100101 Firefox/137.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_7_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.3 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/135.0.0.0 Safari/537.36 Edg/135.0.3179.54"
]

SEARCH_ENGINES = [
    {"name": "Ahmia", "url": "http://juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion/search/?q={query}"},
    {"name": "OnionLand", "url": "http://3bbad7fauom4d6sgppalyqddsqbf5u5p56b5k5uk2zxsy3d6ey2jobad.onion/search?q={query}"},
    {"name": "Torgle", "url": "http://iy3544gmoeclh5de6gez2256v6pjh4omhpqdh2wpeeppjtvqmjhkfwad.onion/torgle/?query={query}"},
    {"name": "Amnesia", "url": "http://amnesia7u5odx5xbwtpnqk3edybgud5bmiagu75bnqx2crntw5kry7ad.onion/search?query={query}"},
    {"name": "Kaizer", "url": "http://kaizerwfvp5gxu6cppibp7jhcqptavq3iqef66wbxenh6a2fklibdvid.onion/search?q={query}"},
    {"name": "Anima", "url": "http://anima4ffe27xmakwnseih3ic2y7y3l6e7fucwk4oerdn4odf7k74tbid.onion/search?q={query}"},
    {"name": "Tornado", "url": "http://tornadoxn3viscgz647shlysdy7ea5zqzwda7hierekeuokh5eh5b3qd.onion/search?q={query}"},
    {"name": "TorNet", "url": "http://tornetupfu7gcgidt33ftnungxzyfq2pygui5qdoyss34xbgx2qruzid.onion/search?q={query}"},
    {"name": "Torland", "url": "http://torlbmqwtudkorme6prgfpmsnile7ug2zm4u3ejpcncxuhpu4k2j4kyd.onion/index.php?a=search&q={query}"},
    {"name": "Find Tor", "url": "http://findtorroveq5wdnipkaojfpqulxnkhblymc7aramjzajcvpptd4rjqd.onion/search?q={query}"},
    {"name": "Excavator", "url": "http://2fd6cemt4gmccflhm6imvdfvli3nf7zn6rfrwpsy7uhxrgbypvwf5fad.onion/search?query={query}"},
    {"name": "Onionway", "url": "http://oniwayzz74cv2puhsgx4dpjwieww4wdphsydqvf5q7eyz4myjvyw26ad.onion/search.php?s={query}"},
    {"name": "Tor66", "url": "http://tor66sewebgixwhcqfnp5inzp5x5uohhdy3kvtnyfxc2e5mxiuh34iid.onion/search?q={query}"},
    {"name": "OSS", "url": "http://3fzh7yuupdfyjhwt3ugzqqof6ulbcl27ecev33knxe3u7goi3vfn2qqd.onion/oss/index.php?search={query}"},
    {"name": "Torgol", "url": "http://torgolnpeouim56dykfob6jh5r2ps2j73enc42s2um4ufob3ny4fcdyd.onion/?q={query}"},
    {"name": "The Deep Searches", "url": "http://searchgf7gdtauh7bhnbyed4ivxqmuoat3nm6zfrg3ymkq6mtnpye3ad.onion/search?q={query}"},
]

# Backward-compatible flat list used by existing search logic
DEFAULT_SEARCH_ENGINES = [e["url"] for e in SEARCH_ENGINES]

def get_tor_session():
    session = requests.Session()
    retry = Retry(
        total=1,
        read=1,
        connect=1,
        backoff_factor=0.5,
        status_forcelist=[500, 502, 503, 504]
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.proxies = {
        "http": os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050"),
        "https": os.environ.get("TOR_PROXY", "socks5h://127.0.0.1:9050")
    }
    return session

ONION_V3_HOST = re.compile(r"^[a-z2-7]{56}\.onion$", re.ASCII)


def fetch_search_results(endpoint, query, engine_name=None):
    encoded_query = quote_plus(str(query)[:2_000])
    url = endpoint.format(query=encoded_query)
    headers = {"User-Agent": secrets.choice(USER_AGENTS)}
    session = get_tor_session()

    try:
        response = session.get(url, headers=headers, timeout=10)
        if response.status_code == 200:
            soup = BeautifulSoup(response.text, "html.parser")
            links = []
            # Parse endpoint host for redirect unwrapping
            endpoint_parsed = urlparse(url)
            endpoint_host = (endpoint_parsed.hostname or "").lower()

            for a in soup.find_all('a', href=True):
                try:
                    href = unquote(str(a['href']))
                    title = a.get_text(strip=True)
                    # Extract onion links (improved regex for v3 addresses)
                    link = re.findall(r'https?:\/\/[a-z2-7]{56}\.onion[^\s"\'<>]*', href, re.I)
                    if len(link) != 0:
                        matched_url = link[0]
                        matched_parsed = urlparse(matched_url)
                        matched_host = (matched_parsed.hostname or "").lower()

                        # If the link is a redirect pointing back to the search engine,
                        # extract the real target from query parameters
                        if matched_host == endpoint_host:
                            qs = parse_qs(matched_parsed.query)
                            found_nested = False
                            for vals in qs.values():
                                for val in vals:
                                    if ".onion" in val:
                                        nested_links = re.findall(r'https?:\/\/[a-z2-7]{56}\.onion[^\s"\'<>]*', unquote(val), re.I)
                                        if nested_links:
                                            matched_url = nested_links[0]
                                            matched_parsed = urlparse(matched_url)
                                            matched_host = (matched_parsed.hostname or "").lower()
                                            found_nested = True
                                            break
                                if found_nested:
                                    break

                        if matched_parsed.scheme not in {"http", "https"} or not ONION_V3_HOST.fullmatch(matched_host):
                            continue
                        if matched_parsed.username or matched_parsed.password:
                            continue
                        matched_path = matched_parsed.path.rstrip('/')
                        is_self_ref = matched_host == endpoint_host
                        is_utility = matched_path in (
                            "/about", "/contact", "/directory", "/last-added",
                            "/advertising", "/advertise", "/webmaster", "/search", ""
                        )

                        # Filter out self-referential utility pages
                        if is_self_ref and is_utility:
                            continue

                        # Only drop URLs whose path is exactly /search
                        is_search_page = matched_parsed.path.rstrip('/') == '/search'

                        # Title quality: 4+ chars, alphanumeric, max 200 chars
                        has_alphanum = bool(re.search(r'[a-zA-Z0-9]', title))
                        title_ok = len(title) >= 4 and has_alphanum and len(title) <= 200

                        if not is_search_page and title_ok:
                            links.append({"title": title, "link": matched_url, "source_engine": engine_name or endpoint_host})
                except (KeyError, TypeError, ValueError):
                    continue
            return links
        else:
            return []
    except requests.RequestException:
        return []

def get_search_results(refined_query, max_workers=5):
    results = []
    bounded_workers = max(1, min(int(max_workers), 16))
    with ThreadPoolExecutor(max_workers=bounded_workers) as executor:
        futures = {
            executor.submit(fetch_search_results, engine["url"], refined_query, engine["name"]): engine["name"]
            for engine in SEARCH_ENGINES
        }
        for future in as_completed(futures):
            result_urls = future.result()
            for item in result_urls:
                item.setdefault("source_engine", futures[future])
            results.extend(result_urls)

    # Deduplicate results — normalize to scheme+host+path (strip query params,
    # fragments, URL-encoding) so tracker-tagged variants merge into one
    seen_links = set()
    unique_results = []
    for res in results:
        link = res.get("link") or ""
        try:
            parsed = urlparse(link)
            norm_host = unquote(parsed.hostname or "").lower()
            norm_path = unquote(parsed.path.rstrip('/'))
            clean_link = f"{parsed.scheme}://{norm_host}{norm_path}"
        except Exception:
            clean_link = link.rstrip('/')
        if clean_link not in seen_links:
            seen_links.add(clean_link)
            unique_results.append(res)

    return unique_results
