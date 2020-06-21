# -*- coding: utf-8 -*-
"""
整个用来加密的包
"""

import base64
from Crypto.Cipher import AES
import chat_rsa, rsa

import random

def pkcs7padding(text):
    '''
    明文使用 PKCS7 填充
    调用 AES 加密时，传入的是字节数组，要求是 16 的整数倍
    不是 16 字节整数倍的需要填充
    '''
    bs = AES.block_size # 16
    length = len(text)
    bytes_length = len(bytes(text, encoding='utf-8'))
    # utf-8 编码，英文 1 byte，中文 3 byte
    # padding_size = length if (bytes_length == length) else bytes_length
    # 需要填充的字符长度
    padding = 128 - bytes_length
    print('message length', bytes_length, 'padding length', padding)
    # 填充的字符
    padding_text = chr(padding) * padding
    return text + padding_text

def pkcs7unpadding(text):
    '''
    处理使用 pkcs7 填充过的数据
    '''
    length = len(text)
    unpadding = ord(text[length-1])
    return text[0:length-unpadding]

def encrypt(key, content, prikeyname):
    '''
    AES 加密，key iv同一个
    模式： cbc
    填充： pkcs7
    '''
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    ciper = AES.new(key_bytes, AES.MODE_CBC, iv)
    # AES 加密处理明文
    content_padding = pkcs7padding(content)
    
    my_pri_key = chat_rsa.get_private_key(prikeyname)

    my_sign = rsa.sign(content_padding.encode(), my_pri_key, 'SHA-1')
    print('Have signed with', prikeyname)

    all_content = bytes(content_padding, encoding='utf-8') + my_sign

    # 加密
    # encrypt_bytes = ciper.encrypt(bytes(content_padding, encoding='utf-8'))
    encrypt_bytes = ciper.encrypt(all_content)
    # 重新编码
    result = str(base64.b64encode(encrypt_bytes), encoding='utf-8')
    return result

def decrypt(key, content, pubkeyname):
    '''
    解密
    '''
    key_bytes = bytes(key, encoding='utf-8')
    iv = key_bytes
    cipher = AES.new(key_bytes, AES.MODE_CBC, iv)
    # base64解码
    encrypt_bytes = base64.b64decode(content)
    # 解密
    decrypt_bytes = cipher.decrypt(encrypt_bytes)
    # 重新编码
    result = str(decrypt_bytes[:128], encoding='utf-8')

    # 验证签名
    pubkey = chat_rsa.get_public_key(pubkeyname)
    
    his_sign = decrypt_bytes[128:256]
    
    verify = rsa.verify(bytes(result, encoding='utf-8'), decrypt_bytes[128:256], pubkey)
    print('Checking Sign......')
    if verify:
        print('Checking Sign Successfully: ', verify)
    else:
        print('Checking Failed!!!')

    # 去除填充内容
    result = pkcs7unpadding(result)
    return result

def get_key(n):
    '''
    生成密钥，n 为密钥的长度
    '''
    c_length = int(n)
    source = 'ABCDEFGHJKMNPQRSTWXYZabcdefhijkmnprstwxyz2345678'
    length = len(source)-1
    result = ''
    for i in range(c_length):
        result += source[random.randint(0, length)]
    return result

if __name__ == '__main__':
    # 生成密钥
    # aes_key = get_key(16)
    aes_key = 'GENjnwZR4p2M5saR'
    print('key:', aes_key)

    # 加密
    source_en = 'Hello!'
    encrypt_en = encrypt(aes_key, source_en, 'chat1_pri.pem')
    print('before encrypt:', source_en)
    print('after encrypt:', encrypt_en)

    # 解密
    decrypt_en = decrypt(aes_key, encrypt_en, 'chat1_pub.pem')
    print('after decrypt:',decrypt_en)
    print(decrypt_en == source_en)
    




