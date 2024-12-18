1,Recon
port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 7.4p1 Debian 10+deb9u6 (protocol 2.0)
| ssh-hostkey: 
|   2048 6d:7c:81:3d:6a:3d:f9:5f:2e:1f:6a:97:e5:00:ba:de (RSA)
|   256 99:7e:1e:22:76:72:da:3c:c9:61:7d:74:d7:80:33:d2 (ECDSA)
|_  256 6a:6b:c3:8e:4b:28:f7:60:85:b1:62:ff:54:bc:d8:d6 (ED25519)
80/tcp   open  http    Apache httpd 2.4.25 ((Debian))
|_http-server-header: Apache/2.4.25 (Debian)
|_http-title: Apache2 Debian Default Page: It works
1337/tcp open  waste?
| fingerprint-strings: 
|   DNSStatusRequestTCP: 
|     08:46:13 up 2 min, 0 users, load average: 0.04, 0.06, 0.02
|   DNSVersionBindReqTCP: 
|     08:46:08 up 2 min, 0 users, load average: 0.05, 0.07, 0.02
|   GenericLines: 
|     08:45:57 up 2 min, 0 users, load average: 0.06, 0.07, 0.02
|     What do you want me to echo back?
|   GetRequest: 
|     08:46:03 up 2 min, 0 users, load average: 0.05, 0.07, 0.02
|     What do you want me to echo back? GET / HTTP/1.0
|   HTTPOptions: 
|     08:46:03 up 2 min, 0 users, load average: 0.05, 0.07, 0.02
|     What do you want me to echo back? OPTIONS / HTTP/1.0
|   Help: 
|     08:46:18 up 2 min, 0 users, load average: 0.04, 0.06, 0.02
|     What do you want me to echo back? HELP
|   NULL: 
|     08:45:57 up 2 min, 0 users, load average: 0.06, 0.07, 0.02
|   RPCCheck: 
|     08:46:03 up 2 min, 0 users, load average: 0.05, 0.07, 0.02
|   RTSPRequest: 
|     08:46:03 up 2 min, 0 users, load average: 0.05, 0.07, 0.02
|     What do you want me to echo back? OPTIONS / RTSP/1.0
|   SSLSessionReq, TLSSessionReq, TerminalServerCookie: 
|     08:46:18 up 2 min, 0 users, load average: 0.04, 0.06, 0.02
|_    What do you want me to echo back?
1 service unrecognized despite returning data. If you know the service/version, please submit the following fingerprint at https://nmap.org/cgi-bin/submit.cgi?new-service
```

Page check
![](images/Pasted%20image%2020241218085304.png)
The index page is the original page of service of `Apache debian2`

