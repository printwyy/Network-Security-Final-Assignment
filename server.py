# -*- encoding: utf-8 -*-
import socket
from creatersa import *
from safetools import *

spk,ssk=create_rsa_pair(is_save=False)

IP = "localhost"  # 服务器端可以写"localhost"，可以为空字符串""，可以为本机IP地址
port = 40005  # 端口号
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((IP, port))
s.listen(1)
print('listen at port :', port)
conn, addr = s.accept()
print('connected by', addr)
count=1
cpk=''


while True:
	print("send-recv count:"+str(count))
	print("等待对方...")

	if count==1:
		print("交换公钥阶段")
		data = conn.recv(1024)
		data = data.decode()  # 解码
		if not data or data == 'exit':
			print("对方已结束")
			break
		print('received', data)
		cpk=data
		send=spk.decode()
	else:
		data = conn.recv(1024)
		data = data.decode()  # 解码
		print(data)
		if not data or data == 'exit':
			print("对方已结束")
			break
		M, signature_HM, k = outdataEnvelope(data, ssk)
		# RSA公钥验证
		HM = to_verify(signature_HM, M, cpk)
		if (HM):
			print("哈希值相同,消息安全传输成功!:" + M)
		else:
			print("安全传输失败!")
		if not M or M == 'exit':
			break
		print('received message:',M)
		send = input('send:')
		key = randomkey()
		link_message = sign_link(ssk, send)
		send = indataEnvelope(link_message, key, cpk)

	conn.sendall(send.encode())  # 再编码发送
	count+=1



conn.close()
s.close()
