#
# python3
from hashlib import pbkdf2_hmac
import base64

password = bytes("", "utf-8")
data = bytes("", "utf-8")
length = 23
round = 13
res = b''

key = password
while len(res) < length:
	h = pbkdf2_hmac('sha256', key, data, round, length)
	key = h
	res = res + key

res = base64.urlsafe_b64encode(res[:length])
print(res.decode()[:length])
