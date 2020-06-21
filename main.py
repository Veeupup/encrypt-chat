# -*- coding: utf-8 -*-

import configparser
import socket, threading
import myencrypt

# HOST_ANOTHER = '127.0.0.1'
IS_CHATTING = False
PORT_ANOTHER = 2000
AES_KEY = ''

# 读取配置文件
def get_cfg():
    config = configparser.ConfigParser()
    config.read('chat1.cfg', encoding='utf-8')
    port = config.get('config','port')
    host = config.get('config', 'host')

    global AES_KEY
    AES_KEY = config.get('config', 'aes-key')

    return host, int(port)

# 监听接收线程
def chat_server(host ,port):
    print(host, port, 'is listening......')
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((host, port))
        s.listen()
        conn, addr = s.accept()

        print('ip:', addr, 'has connected')

        global IS_CHATTING
        
        # 如果不在通话，那么就开始读取输入并且发送
        if not IS_CHATTING:
            threading.Thread(target=chat_client, args=(str(addr), PORT_ANOTHER), name='client').start()
        
        while True:
            data = conn.recv(512)
            print('=======================')
            print('raw data from', str(addr), data)
            decrypt_data = myencrypt.decrypt(AES_KEY, data, 'chat2_pub.pem')
            print('after decrypt:', decrypt_data)
            print('=======================')
            if not data:
                break 

# 发送数据线程     
def chat_client(host, port):

    global IS_CHATTING, AES_KEY
    IS_CHATTING = True

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((str(host), int(PORT_ANOTHER)))
        while True:
            con = input()
            
            print('=======================')
            print('raw text:', con)
            # AES 加密的密钥，加密内容，自己用于签名的私钥
            encrypt_con = myencrypt.encrypt(AES_KEY, con, 'chat1_pri.pem')
            print('after aes encrypt:', encrypt_con)
            print('send it...')
            if con == 'bye':
                s.close()
                break
            s.sendall(encrypt_con.encode('utf-8'))
            print('=======================')
            
if __name__ == "__main__":

    HOST ,PORT = get_cfg()
    print('aes key:', AES_KEY)

    threading.Thread(target=chat_server, args=(HOST, PORT), name='server').start()
    
    call_or_wait = input("input 'y' to call, input 'c' to wait: ")

    # 选择拨号
    if call_or_wait == 'y':

        to_host = input('input the host who you want to talk to:')

        # 这里为了本机测试，直接写成 2000
        threading.Thread(target=chat_client, args=(to_host, 2000), name='chat_client').start() 

    elif call_or_wait == 'c':

        print('now waiting for someone to call')

    else:

        print('please input y or c')

        
    
