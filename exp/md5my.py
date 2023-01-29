# -*-coding:UTF-8 -*-
from math import floor, sin
from bitarray import bitarray
from enum import Enum
import struct


# 初始化MD5缓冲区
class Buffer(Enum):
    A = 0x67452301
    B = 0xEFCDAB89
    C = 0x98BADCFE
    D = 0x10325476


class MyMd5(object):
    buffers = {Buffer.A: None, Buffer.B: None,
               Buffer.C: None, Buffer.D: None,
               }

    @classmethod
    # 消息填充
    def message_fill(cls):
        bit = bitarray(endian="big")
        bit.frombytes(cls.string_M.encode("utf-8"))
        bit.append(1)

        while bit.length() % 512 != 448:  # 如果mod512不等于448,填充0
            bit.append(0)

        return bitarray(bit, endian="little")  # 小端

    @classmethod
    # 附加消息的长度
    def additional_message_length(cls, message_fill_result):
        length = (len(cls.string_M) * 8) % pow(2, 64)

        # 将length转成64bit的小端形式
        message_length = bitarray(endian="little")
        message_length.frombytes(struct.pack("<Q", length))
        result = message_fill_result.copy()
        result.extend(message_length)

        return result

    @classmethod
    # 对MD5缓冲区初始化
    def buffer_initialize(cls):
        for buffer_type in cls.buffers.keys():
            cls.buffers[buffer_type] = buffer_type.value

        A = cls.buffers[Buffer.A]
        B = cls.buffers[Buffer.B]
        C = cls.buffers[Buffer.C]
        D = cls.buffers[Buffer.D]

    @classmethod
    # 以分组为单位对消息进行处理
    def message_handing(cls, additional_message_length_result):
        # 定义循环左移函数
        ROL = lambda x, n: (x << n) | (x >> (32 - n))

        # 定义模加函数
        mod_add = lambda a, b: (a + b) % pow(2, 32)

        # 定义逻辑函数
        F = lambda x, y, z: (x & y) | (~x & z)
        G = lambda x, y, z: (x & z) | (y & ~z)
        H = lambda x, y, z: x ^ y ^ z
        I = lambda x, y, z: y ^ (x | ~z)

        # 计算常数表T
        T = [floor(pow(2, 32) * abs(sin(i + 1))) for i in range(64)]

        # 将附加后的明文长度分成32位的块
        N = len(additional_message_length_result) // 32

        for block in range(N // 16):
            # 在列表blocks中将明文分成16个32位的块
            start = block * 512
            blocks = [additional_message_length_result[start + (x * 32):
                                                       start + (x * 32) + 32] for x in range(16)]

            blocks = [int.from_bytes(word.tobytes(), byteorder="little") for word in blocks]

            # 定义缓冲区
            A = cls.buffers[Buffer.A]
            B = cls.buffers[Buffer.B]
            C = cls.buffers[Buffer.C]
            D = cls.buffers[Buffer.D]

            # 4轮处理
            for i in range(4 * 16):
                # 1
                if 0 <= i <= 15:
                    k = i
                    s = [7, 12, 17, 22]
                    temp = F(B, C, D)
                # 2
                elif 16 <= i <= 31:
                    k = ((5 * i) + 1) % 16
                    s = [5, 9, 14, 20]
                    temp = G(B, C, D)
                # 3
                elif 32 <= i <= 47:
                    k = ((3 * i) + 5) % 16
                    s = [4, 11, 16, 23]
                    temp = H(B, C, D)
                # 4
                elif 48 <= i <= 63:
                    k = (7 * i) % 16
                    s = [6, 10, 15, 21]
                    temp = I(B, C, D)

                # 执行循环左移与模加
                temp = mod_add(temp, blocks[k])
                temp = mod_add(temp, T[i])
                temp = mod_add(temp, A)
                temp = ROL(temp, s[i % 4])
                temp = mod_add(temp, B)

                # 下一轮操作
                A = D
                D = C
                C = B
                B = temp

            # 更新缓冲区
            cls.buffers[Buffer.A] = mod_add(cls.buffers[Buffer.A], A)
            cls.buffers[Buffer.B] = mod_add(cls.buffers[Buffer.B], B)
            cls.buffers[Buffer.C] = mod_add(cls.buffers[Buffer.C], C)
            cls.buffers[Buffer.D] = mod_add(cls.buffers[Buffer.D], D)

    @classmethod
    # 输出
    def Output(cls):
        A = struct.unpack("<I", struct.pack(">I", cls.buffers[Buffer.A]))[0]
        B = struct.unpack("<I", struct.pack(">I", cls.buffers[Buffer.B]))[0]
        C = struct.unpack("<I", struct.pack(">I", cls.buffers[Buffer.C]))[0]
        D = struct.unpack("<I", struct.pack(">I", cls.buffers[Buffer.D]))[0]

        # 输出缓冲区
        return f"{format(A, '08x')}{format(B, '08x')}{format(C, '08x')}{format(D, '08x')}"

    @classmethod
    # 压缩函数
    def MyHash(cls, string_M):
        cls.string_M = string_M
        preprocessed_bit_array = cls.additional_message_length(cls.message_fill())
        cls.buffer_initialize()
        cls.message_handing(preprocessed_bit_array)
        return cls.Output()

