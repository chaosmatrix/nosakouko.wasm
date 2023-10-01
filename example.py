#
# python3
from hashlib import pbkdf2_hmac
import base64

key = bytes("******", "utf-8")
data = bytes("bbbbbbbbccccccccdddddddd", "utf-8")
length = 23
round = 13
res = ""
h = pbkdf2_hmac('sha256', key, data, round, length)
key = h

res = base64.urlsafe_b64encode(key)[:length]
print(res.decode())
