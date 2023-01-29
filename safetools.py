# -- coding: utf-8 --
from desnew import *
from creatersa import *
import random

def randomkey():
    return str(random.randint(10000000,99999999))

def indataEnvelope(text,key,pk):
    s = des_en(key, text)
    print('DES对M||signature[H(M)]加密后结果:\n' + hex(int(s, 16)) + '\n')
    ck = encryption(key, pk)
    linkm = s + '|' + ck
    return linkm

def outdataEnvelope(linkm,sk):
    l = 0
    for i in linkm:
        l += 1
        if i == '|':
            break
    lk = linkm[l:]
    s = linkm[:l - 1]
    k = decryption(lk, sk)
    link_message = des_de(k, s) #拆信封
    print('DES解密得到M||signature[H(M)||lenm]:\n' + link_message + '\n')
    l2 = 0
    for i in reversed(link_message):
        l2 -= 1
        if i == '@':
            break
    lenm = int(link_message[l2 + 1:])
    M2 = link_message[:lenm]
    signature_HM = link_message[lenm + 1:l2:]
    print("拆分后得到的消息M为: ", M2, '\n')
    print("拆分后得到的signature[H(M)]:\n", signature_HM, '\n')
    print("拆分后得到的k:\n", k, '\n')
    return M2,signature_HM,k

def sign_link(sk,M):
    len_m = len(M)
    # RSA私钥签名
    signature_HM = to_sign(M, sk)
    print('signature[H(M)]:\n' + signature_HM + '\n')

    # 消息与签名后的结果链接
    link_message = M + '@' + signature_HM + '@' + str(len_m)
    print('M||signature[H(M)]:\n' + link_message + '\n')
    return link_message


if __name__ == "__main__":
    M="hello it's me!"

    key =randomkey() #'52345608'
    pk,sk=create_rsa_pair(is_save=False)
    link_message=sign_link(sk,M)

    linkm=indataEnvelope(link_message,key,pk)

    M2, signature_HM, k=outdataEnvelope(linkm,sk)

    #RSA公钥验证
    HM=to_verify(signature_HM,M2,pk)

    if(HM):
        print("哈希值相同,文件安全传输成功!:"+M2)
    else:
        print("文件安全传输失败!")
