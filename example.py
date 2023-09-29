import hashlib,hmac,base64

key = ""
data = ""
length = 23
round = 2
res = ""
for i in range(round):
	h = hmac.new(key, data, hashlib.sha256)
	key = h.digest()
res = base64.urlsafe_b64encode(h.digest())[:length]
print(res)
