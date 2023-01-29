
import base64

import pyDes
import binascii  # 二进制和 ASCII 码互转
    # 加密
def des_en(k,text):
    iv = secret_key = k
    k = pyDes.des(secret_key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
    data = k.encrypt(text, padmode=pyDes.PAD_PKCS5)
    # data.进制返回文本字符串.解码字符串
    return binascii.b2a_hex(data).decode()

    # 解密
def des_de(k,text):
    iv = secret_key =k
    k = pyDes.des(secret_key, pyDes.CBC, iv, pad=None, padmode=pyDes.PAD_PKCS5)
    data = k.decrypt(binascii.a2b_hex(text), padmode=pyDes.PAD_PKCS5)
    return data.decode()


if __name__ == "__main__":
    input_text = 'LGK'

    k='12345678'
    encode_str = des_en(k,input_text.encode())
    print('加密后：', encode_str)

    decode_str = des_de(k,encode_str)
    print('解密后：', decode_str)

