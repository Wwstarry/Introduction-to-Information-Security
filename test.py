from flask import Flask, request, jsonify, render_template
import os

import socketio
from S_AES import S_AES  # AES 加密逻辑
from S_DES import S_DES  # DES 加密逻辑
from werkzeug.utils import secure_filename
import multiprocessing
import logging
from flask_socketio import SocketIO
from multi_brute_force import Multi_bruteForce_16, divide_task_16bit

# 创建S_AES实例
aes_cipher = S_AES()

# 设置密钥 (16位二进制数)
key = [int(x) for x in '0101010110101010']
aes_cipher.SetKey(key)

# 明文 "hello world 123"
plaintext = "hello world 123"

# 使用 ASCII 加密
encrypted_result = aes_cipher.Encryption_ASCII(plaintext)
print(f"加密结果: {encrypted_result}")

