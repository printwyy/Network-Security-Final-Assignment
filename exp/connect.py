# -- coding: utf-8 --

from exp.md5py import *
from exp.desnew import *
from exp.creatersa import *

if __name__ == "__main__":
    M="hello it's me!"
    key = '52345608'
    #(pk,pkn)=generate_publickey()
    #(sk,skn)=generate_privatekey()
    pk,sk=create_rsa_pair(is_save=False)

    print("M: "+M+'\n')
    len_M=len(M)

    #对消息哈希
    #HM=md5_string(M)
    #print("Hash(M): "+HM+'\n')

    #RSA私钥签名
    signature_HM=to_sign(M,sk)#signature(HM,sk,skn)
    print('signature[H(M)]:\n'+signature_HM+'\n')

    #消息与签名后的结果链接
    link_message=M+'@'+signature_HM+'@'+str(len_M)
    print('M||signature[H(M)]:\n'+link_message+'\n')

    #DES加密
    print('DES key: '+key+'\n')
    s=des_en(key,link_message)#DES_encrypt(link_message,key)
    print('DES对M||signature[H(M)]加密后结果:\n' + hex(int(s, 16)) + '\n')
    #print('DES对M||signature[H(M)]加密后的16进制结果:\n'+hex(int(s,2))+'\n')

    ck=encryption(key,pk)#encorp(key,pk,pkn)
    #print('l='+str(len(ck)))

    linkm=s+'|'+ck
    l = 0
    for i in linkm:
        l += 1
        if i == '|':
            break
    lk = linkm[l:]
    s=linkm[:l-1]

    k=decryption(lk,sk)#decrop(lk,sk,skn)

    print('密码加密：'+ck)
    print('解密：'+k)
    #DES解密
    link_message=des_de(k,s)#DES_decrypt(s,key)
    print('DES解密得到M||signature[H(M)||lenm]:\n'+link_message+'\n')

    #消息拆分
    l2 = 0
    for i in reversed(link_message):
        l2 -= 1
        if i == '@':
            break
    lenm=int(link_message[l2+1:])
    M2 = link_message[:lenm]
    signature_HM = link_message[lenm + 1:l2:]

    print("拆分后得到的消息M为: ",M2,'\n')
    print("拆分后得到的signature[H(M)]:\n",signature_HM,'\n')
    print("拆分后得到的k:\n", lk, '\n')

    #RSA公钥验证
    HM=to_verify(signature_HM,M2,pk)#verify(signature_HM,pk,pkn)
    #print("对拆分后的数字签名进行RSA公钥验证: "+HM+'\n')

    #对拆分后的消息哈希
    #HM1=md5_string(M)
    #print("对拆分后的消息M哈希: "+HM1+'\n')

    if(HM):
        print("哈希值相同,文件安全传输成功!:"+M2)
    else:
        print("文件安全传输失败!")
