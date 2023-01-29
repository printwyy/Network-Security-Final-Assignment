# -*- coding: utf-8 -*-
import rsa

# rsa加密
def rsak(): # 生成公钥、私钥
    (pubkey, privkey) = rsa.newkeys(1024)
    print("pub: ", pubkey)
    print("priv: ", privkey)
    return pubkey,privkey

def rsaEncrypt(str,pubkey):
    # 明文编码格式
    content = str.encode('gb18030')
    # 公钥验证
    crypto = rsa.encrypt(content, pubkey)
    return crypto


# rsa解密
def rsaDecrypt(str, sk):
    # 私钥签名
    content = rsa.decrypt(str, sk)
    con = content.decode('utf-8')
    return con

def signrse(message,sk):
    signature = rsa.sign(message.encode('utf-8'),sk, 'SHA-1')
    return signature

def verifyrse(message,s,pk):
    r=rsa.verify(message.encode('utf-8'), s, pk)
    return r
if __name__ == "__main__":
    (a, b) = rsak()
    e=rsaEncrypt("hello",a)
    print('加密后密文：')
    print(e)
    content = rsaDecrypt(e, b)
    print('解密后明文：')
    print(content)

    m="hello"
    s=signrse(m,b)
    r=verifyrse(m,s,a)
    print(r)