# -*- coding: utf-8 -*-

import rsa

def get_private_key(filename):
    '''
    本地加载私钥文件
    '''
    prikey = ''
    with open(filename, 'r') as f:
        prikey = rsa.PrivateKey.load_pkcs1(f.read().encode())
    
    return prikey

def get_public_key(filename):
    '''
    本地加载公钥文件
    '''
    pubkey = ''
    with open(filename, 'r')  as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())
    
    return pubkey

def generate_key(n, filename):
    '''
    生成密钥文件
    '''
    pub_key, pri_key= rsa.newkeys(n)

    pri_filename = str(filename) + '_pri.pem' # 私钥名称
    pub_filename = str(filename) + '_pub.pem' # 公钥名称

    with open(pri_filename, 'w+') as f:
        f.write(pri_key.save_pkcs1().decode())

    with open(pub_filename, 'w+') as f:
        f.write(pub_key.save_pkcs1().decode())

def test_load():
    prikey = ''
    pubkey = ''
    with open('chat1_pri.pem', 'r') as f:
        prikey = rsa.PrivateKey.load_pkcs1(f.read().encode())
    
    with open('chat1_pub.pem', 'r') as f:
        pubkey = rsa.PublicKey.load_pkcs1(f.read().encode())

    print(prikey)
    print(pubkey)

    message = 'hello'

    sign = rsa.sign(message.encode(), prikey, 'SHA-1')
    print(len(sign))
    print(sign)
    verify = rsa.verify(message.encode(), sign, pubkey)
    print(verify)

def test():
    '''
    测试
    '''
        # 生成密钥
    key = rsa.newkeys(1024) 

    # 得到公钥和私钥
    pri_key = key[1]    
    pub_key = key[0]
    print('private_key:',pri_key)
    print('public_key:',pub_key)

    text = 'hello'
    print('before RSA encrypt:', text)
    text = text.encode()

    # 加密
    encrypt_text = rsa.encrypt(text, pub_key)
    print('after RSA encrypt:', encrypt_text)

    # 解密
    decrypt_text = rsa.decrypt(encrypt_text, pri_key)
    text = decrypt_text.decode()
    print('after RSA decrypt:', text)

    # 签名
    text = 'hello'.encode('utf-8')
    signature = rsa.sign(text, pri_key, 'SHA-1')
    verification = rsa.verify(text ,signature, pub_key)
    print(verification)
    signature = [len(signature)-2]
    try: 
        verification = rsa.verify(text ,signature, pub_key)
    except Exception as e:
        print('Error:', e)
        print('oh no')
    
if __name__ == '__main__':
    # 用于测试
    # test()
    # 生成两个用户的公钥和私钥
    # generate_key(1024, 'chat1')
    # generate_key(1024, 'chat2')
    test_load()



    



