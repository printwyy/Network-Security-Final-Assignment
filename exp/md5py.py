import hashlib


# md5加密
def md5_string(in_str):
    md5 = hashlib.md5()
    md5.update(in_str.encode("utf8"))
    result = md5.hexdigest()
    return result


if __name__ == '__main__':
    str_in = '加密前的数据'
    print("加密后：", md5_string(str_in))
