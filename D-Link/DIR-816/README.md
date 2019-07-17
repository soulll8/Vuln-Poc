# D-Link DIR-816 A2 Stack Overflow 
#### Vender & Firmware version ：D-Link 1.10 B05 
#### CVE-ID : CVE-2018-20305
#### Author: ADLab of Venustech
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
More details, as the Vendor did not fix, will not be disclosed here.
