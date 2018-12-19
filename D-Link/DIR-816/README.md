# D-Link DIR-816 A2 Stack Overflow
##### Vender ：D-Link 
##### Firmware version:1.10 B05 
##### Exploit Author: ScareCrowL 
##### Hardware Link:http://support.dlink.com.cn/ProductInfo.aspx?m=DIR-816 
# Vulnerability Description
Stack-based buffer overflows found on d-link dir-816 A2 1.10 B05 devices allow arbitrary remote code execution without authentication.Embodied in the /goform/form2userconfig.cgi handler function, long password may lead to stack-based buffer overflow and cover the return address.
