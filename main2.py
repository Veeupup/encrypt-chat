# -*- coding: utf-8 -*-

import configparser
import socket, threading
import aes

IS_CHATTING = False
# HOST_ANOTHER = '127.0.0.1'
PORT_ANOTHER = 1000
AES_KEY = ''

def get_cfg():
    config = configparser.ConfigParser()
    config.read('chat2.cfg', encoding='utf-8')
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

        if not IS_CHATTING:
            threading.Thread(target=chat_client, args=(addr, PORT_ANOTHER), name='client').start()
        
        global AES_KEY

        while True:
            data = conn.recv(64)
            print('=======================')
            print('raw data from', str(addr), data)
            decrypt_data = aes.decrypt(AES_KEY, data)
            print('after decrypt:', decrypt_data)
            print('=======================')
            if not data:
                break 
            
# 发送数据线程     
def chat_client(host, port):

    global IS_CHATTING
    IS_CHATTING = True

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('127.0.0.1', int(PORT_ANOTHER)))
        while True:
            con = input()
            
            print('=======================')
            print('raw text:', con)
            encrypt_con = aes.encrypt(AES_KEY, con)
            print('after aes encrypt:', encrypt_con)
            print('send it...')
            if con == 'bye':
                s.close()
                break
            s.sendall(encrypt_con.encode('utf-8'))
            print('=======================')
            

if __name__ == "__main__":

    HOST ,PORT = get_cfg()
    print(AES_KEY)

    threading.Thread(target=chat_server, args=(HOST, PORT), name='server').start()
    
    # to_host = input('input the host who you want to talk to:')

    # 这里为了本机测试，直接写成 1000
    # threading.Thread(target=chat_client, args=(to_host, 1000), name='chat_client').start() 
    
    call_or_wait = input("input 'y' to call, input 'c' to wait: ")

    # 选择拨号
    if call_or_wait == 'y':

        to_host = input('input the host who you want to talk to:')

        # 这里为了本机测试，直接写成 2000
        threading.Thread(target=chat_client, args=(to_host, 1000), name='chat_client').start() 

    elif call_or_wait == 'c':

        print('now waiting for someone to call......')


    else:

        print('please input y or c')
