# -- coding: gb2312 --

p = 106697219132480173106064317148705638676529121742557567770857687729397446898790451577487723991083173010242416863238099716044775658681981821407922722052778958942891831033512463262741053961681512908218003840408526915629689432111480588966800949428079015682624591636010678691927285321708935076221951173426894836169
q = 144819424465841307806353672547344125290716753535239658417883828941232509622838692761917211806963011168822281666033695157426515864265527046213326145174398018859056439431422867957079149967592078894410082695714160599647180947207504108618794637872261572262805565517756922288320779308895819726074229154002310375209


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
def signature(HM):
    HM = int(HM, 16)
    #print('cs:'+str(HM))
    d, n = generate_privatekey()
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
def verify(signature_HM):
    signature_HM = int(signature_HM, 16)
    e,n = generate_publickey()
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
