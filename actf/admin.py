from base64 import *
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from secret import KEY, ADMIN_PASSWORD

def AESdecode(cookie):
    cookie_encrypted = b64decode(cookie)
    iv, padded = cookie_encrypted[:16], cookie_encrypted[16:]
    cipher = AES.new(KEY, AES.MODE_CBC, iv)
    decrypted = cipher.decrypt(padded)
    cookie_json_bytes = unpad(decrypted, 16)
    cookie_json = cookie_json_bytes
    print(cookie_json)

def cbc(cookie):
    cookie_encrypted = b64decode(cookie)
    iv, padded = cookie_encrypted[:16], cookie_encrypted[16:]
    iv = list(iv)
    iv[10] = iv[10] ^ ord('A') ^ ord('a')
    cookie_encrypted = bytes(iv) + padded
    print(b64encode(cookie_encrypted).decode())
    # AESdecode(b64encode(cookie_encrypted))

# username=Admin&password=123

cookie = 'c2FqS0gqkK+sRiTad+vH2fYJD6ehDRTb2vcvtxSCiwQsga7bHbvAWWX5WJpIpBiWibAIWRdwRy+cmoee2yyq5uUnwvpPBTROyE6Ap+OE6crWItTtyYAXGP6TtghDiiZN'
# AESdecode(cookie)
cbc(cookie)