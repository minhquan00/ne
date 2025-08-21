import requests
from concurrent.futures import ThreadPoolExecutor
import threading
import os
import warnings

VN_OUTPUT = "vn.txt"
lock = threading.Lock()
checked = 0
live_count = 0
total = 0

# Tắt cảnh báo SSL khi verify=False
warnings.filterwarnings("ignore", message="Unverified HTTPS request")

API_VN = [
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=http&timeout=3000&country=vn",
    "https://api.proxyscrape.com/v2/?request=getproxies&protocol=https&timeout=3000&country=vn",
    "https://www.proxy-list.download/api/v1/get?type=http&country=VN",
    "https://www.proxy-list.download/api/v1/get?type=https&country=VN",
    "https://proxylist.geonode.com/api/proxy-list?limit=500&country=VN&sort_by=lastChecked&format=textplain",
    "https://openproxylist.xyz/http.txt",
    "https://openproxylist.xyz/https.txt",
    "http://rootjazz.com/proxies/proxies.txt",
    "https://proxyspace.pro/http.txt",
            "http://36.50.134.20:3000/api/proxies",
            "https://api.lumiproxy.com/web_v1/free-proxy/list?page_size=60&page=1&protocol=1&language=en-us",
            "https://api.lumiproxy.com/web_v1/free-proxy/list?page_size=60&page=1&protocol=2&speed=2&uptime=0&language=en-us",
            "http://pubproxy.com/api/proxy?limit=20&format=txt&type=http",
            "http://pubproxy.com/api/proxy?limit=20&format=txt&type=https",
            "https://cdn.jsdelivr.net/gh/proxifly/free-proxy-list@main/proxies/all/data.txt",
]

def fetch_proxies_vn():
    all_proxies = set()
    for i, url in enumerate(API_VN, 1):
        print(f"📡 API {i}/{len(API_VN)}: ")
        try:
            res = requests.get(url, timeout=3)
            if res.status_code != 200:
                print(f"❌ API {i} trả về status {res.status_code}")
                continue
            lines = [line.strip() for line in res.text.splitlines() if ":" in line]
            print(f"⏳ API {i} lấy được {len(lines)} proxy")
            all_proxies.update(lines)
        except Exception as e:
            print(f"❌ Lỗi API {i}: {e}")
    print(f"📥 Tổng proxy VN lấy được: {len(all_proxies)}")
    return list(all_proxies)

def check(proxy, timeout_http=3, timeout_https=3):
    global checked, live_count
    proxy_url = f"http://{proxy}"
    proxies = {"http": proxy_url, "https": proxy_url}
    is_alive = False

    try:
        if requests.get("http://httpbin.org/ip", proxies=proxies, timeout=timeout_http).status_code == 200:
            is_alive = True
    except:
        pass

    try:
        if requests.get("https://httpbin.org/ip", proxies=proxies, timeout=timeout_https, verify=False).status_code == 200:
            is_alive = True
    except:
        pass

    with lock:
        checked += 1
        if is_alive:
            with open(VN_OUTPUT, "a") as f:
                f.write(proxy + "\n")
            live_count += 1
        print(f"✅ {checked}/{total} | Lưu: {live_count}", end="\r", flush=True)

def scan(proxies, threads=20):
    if os.path.exists(VN_OUTPUT):
        os.remove(VN_OUTPUT)
    with ThreadPoolExecutor(max_workers=threads) as executor:
        for proxy in proxies:
            executor.submit(check, proxy)

if __name__ == "__main__":
    print("🚀 Đang lấy danh sách proxy VN từ API...")
    proxy_list = fetch_proxies_vn()

    if not proxy_list:
        print("❌ Không có proxy VN.")
        exit()

    total = len(proxy_list)
    print(f"🔍 Tổng proxy VN: {total}")
    print("⚙️ Đang kiểm tra proxy...\n")
    scan(proxy_list)

    print(f"\n✅ Hoàn tất.")
    print(f"🇻🇳 Proxy VN sống lưu vào: {VN_OUTPUT} | Tổng lưu: {live_count}")
