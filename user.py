# -*- encoding: utf-8 -*-
import socket
import sys
from creatersa import *
from safetools import *
cpk,csk=create_rsa_pair(is_save=False)

IP = 'localhost' #填写服务器端的IP地址
port = 40005 #端口号必须一致
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
try:
    s.connect((IP,port))
except Exception as e:
    print('server not find or not open')
    sys.exit()


count=1
spk=''
while True:
	print("send-recv count:" + str(count))
	if count==1:
		print("交换公钥阶段")
		trigger=cpk.decode()

	else:
		trigger = input("send:")
		if trigger.lower() == 'exit':  # 发送结束连接
			print("已结束")
			break

		key = randomkey()
		link_message = sign_link(csk, trigger)
		trigger = indataEnvelope(link_message, key, spk)
		print("等待对方...")

	s.sendall(trigger.encode())

	data = s.recv(1024)
	data = data.decode()
	print(data)

	if count==1:
		spk=data
	else:
		M, signature_HM, k = outdataEnvelope(data, csk)
		# RSA公钥验证
		HM = to_verify(signature_HM, M, spk)
		if (HM):
			print("哈希值相同,消息安全传输成功!:" + M)
		else:
			print("安全传输失败!")

		print('received:', M)

	count += 1


s.close()
