# -- coding: gb2312 --
from exp.md5py import *
p = 106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169
q = 144819424465842307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209
p1 = 149160165560465632204165003440741961729061755313208449398541512151285272615496135233367518247898975380003278642720329751151577533027888917551973515850132223912499559429538360586702642885684424082342594829867154711788418772927379792879511900103923716114805616578607075810768028927712965063104734208874255680483
q1 = 111474674595816808821395512512383852534106164662490450327161217688600353501600396838352498226404075791341998941693990125908313105424004322638785851291839121391146358428300611572297565628195020287270253577069685765559746881400130759918144472920769577461569443932095281422091672008297480097282015384340960378793

# 扩展欧几里得算法
def extend_gcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, r = extend_gcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, r


# 公钥
def generate_publickey():
    n = p * q
    e = 65537  # e取固定值
    return e, n


# 私钥
def generate_privatekey():
    ph_n = (p - 1) * (q - 1)
    e = 65537
    (x, y, r) = extend_gcd(ph_n, e)
    if y < 0:
        d = y + ph_n  # 直接用加法比%效率要高
    else:
        d = y
    n = p * q
    return d, n


# 私钥签名
def signature(HM,d,n):
    HM = int(HM, 16)
    #print('cs:'+str(HM))
    #d, n = generate_privatekey()
    print('RSA私钥(d,n):\n' + str(d) + ' , ' + str(n) + '\n')
    signature_HM = pow(HM, d, n)
    signature_HM = hex(signature_HM)[2:]

    return signature_HM

def decrop(HM,d,n):
    HM = int(HM, 16)

    print('RSA私钥(d,n):\n' + str(d) + ' , ' + str(n) + '\n')
    signature_HM = pow(HM, d, n)
    signature_HM = hex(signature_HM)[2:]

    return signature_HM

# 公钥验证
def verify(signature_HM,e,n):
    signature_HM = int(signature_HM, 16)
    e,n = generate_publickey()
    print('RSA公钥(e,n):\n' + str(e) + ' , ' + str(n) + '\n')
    HM = pow(signature_HM, e, n)
    HM = hex(HM)[2:]

    return HM

def encorp(signature_HM,e,n):
    signature_HM = int(signature_HM, 16)

    print('RSA公钥(e,n):\n' + str(e) + ' , ' + str(n) + '\n')
    HM = pow(signature_HM, e, n)
    HM = hex(HM)[2:]

    return HM
if __name__ == "__main__":
    M = "hello it's me!"
    key = '12345608'
    (pk, pkn) = generate_publickey()
    (sk, skn) = generate_privatekey()

    print("M: " + M + '\n')
    len_M = len(M)
    HM =md5_string(M)

    # RSA私钥签名
    signature_HM = signature(HM, sk, skn)
    print('signature[H(M)]:\n' + signature_HM + '\n')
    HM = verify(signature_HM, pk, pkn)
    print("对拆分后的数字签名进行RSA公钥验证: " + HM + '\n')