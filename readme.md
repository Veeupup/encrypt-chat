# 加密通信

一个简单的加密通信。

文件说明：
```shell
configs
    chat1.cfg   -- 客户端 1 的配置
    chat2.cfg   -- 客户端 2 的配置
keys
    chat1.cfg       -- 客户端1的配置
    chat1_pri.pem   -- 客户端1的RSA私钥
    chat1_pub.pem   -- 客户端1的RSA公钥
    ...
main.py         -- 客户端1
main2.py        -- 客户端2
myencrypt.py    -- 用于对文件加密解密签名的工具类
chat_rsa.py     -- 用于 rsa 加密的工具类
```

使用 TCP 进行通信，每次发送的报文为一个 256 字节的报文，采用 RSA 对发送的消息签名，使用 AES 对整个报文加密。

目前为了本机测试，分别运行
```shell
# 启动第一个客户端
python main.py 
# 启动第二个客户端
python main2.py
```

## 运行流程简述
分别启动两个客户端之后，如果客户端1选择拨号到另外一个主机的 IP 地址，那么将会建立起 TCP 连接。

随后通过控制台输入，按回车发送消息，在发送消息之前，首先将消息补足为 128 bytes（AES加密明文为 16 的整数倍），然后使用 RSA ，使用自己的私钥对 128 字节的内容进行签名（SHA-1），签名长度也为 128 字节。

将整个 256 字节的内容使用 AES 加密，使用 TCP 发送。

客户端2接收到加密消息之后，首先使用 AES 解密，然后对前128字节进行 AES解密，后128字节为签名信息，将签名信息和前面的内容一起验证签名。

## 报文格式

* 固定长度，将报文分成两个部分，第一个部分为信息，第二个部分为签名部分
签名部分有 128 个字节，将信息部分也设置为 128 个字节，收到之后，按照长度进行区分

## 加密方法

AES 对称加密：<br/>
模式： cbc  <br/>
填充： pkcs7

RSA 非对称加密: <br/>
密钥长度： 1024bit <br/>
摘要算法：SHA-1
