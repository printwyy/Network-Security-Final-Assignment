# -- coding: gb2312 --

p = 149160165560465632204165003440741961729061755313208449398541512151285272615496135233367518247898975380003278642720329751151577533027888917551973515850132223912499559429538360586702642885684424082342594829867154711788418772927379792879511900103923716114805616578607075810768028927712965063104734208874255680483
q = 111474674595816808821395512512383852534106164662490450327161217688600353501600396838352498226404075791341998941693990125908313105424004322638785851291839121391146358428300611572297565628195020287270253577069685765559746881400130759918144472920769577461569443932095281422091672008297480097282015384340960378793


# ��չŷ������㷨
def extend_gcd(a, b):
    if b == 0:
        return 1, 0, a
    else:
        x, y, r = extend_gcd(b, a % b)
        x, y = y, (x - (a // b) * y)
        return x, y, r


# ��Կ
def generate_publickey():
    n = p * q
    e = 65537  # eȡ�̶�ֵ
    return e, n


# ˽Կ
def generate_privatekey():
    ph_n = (p - 1) * (q - 1)
    e = 65537
    (x, y, r) = extend_gcd(ph_n, e)
    if y < 0:
        d = y + ph_n  # ֱ���üӷ���%Ч��Ҫ��
    else:
        d = y
    n = p * q
    return d, n


# ˽Կǩ��
def signature(HM,d,n):
    HM = int(HM, 16)
    #print('cs:'+str(HM))
    #d, n = generate_privatekey()
    print('RSA˽Կ(d,n):\n' + str(d) + ' , ' + str(n) + '\n')
    signature_HM = pow(HM, d, n)
    signature_HM = hex(signature_HM)[2:]

    return signature_HM

def decrop(HM,d,n):
    HM = int(HM, 16)

    print('RSA˽Կ(d,n):\n' + str(d) + ' , ' + str(n) + '\n')
    signature_HM = pow(HM, d, n)
    signature_HM = hex(signature_HM)[2:]

    return signature_HM

# ��Կ��֤
def verify(signature_HM,e,n):
    signature_HM = int(signature_HM, 16)
    #e,n = generate_publickey()
    print('RSA��Կ(e,n):\n' + str(e) + ' , ' + str(n) + '\n')
    HM = pow(signature_HM, e, n)
    HM = hex(HM)[2:]

    return HM

def encorp(signature_HM,e,n):
    signature_HM = int(signature_HM, 16)

    print('RSA��Կ(e,n):\n' + str(e) + ' , ' + str(n) + '\n')
    HM = pow(signature_HM, e, n)
    HM = hex(HM)[2:]

    return HM
