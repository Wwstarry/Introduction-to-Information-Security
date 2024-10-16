import binascii
from flask import Flask, request, jsonify, render_template, Response
import os
import base64

import numpy as np
from S_AES import S_AES
from S_DES import S_DES
from Other_cipher import S_ECC,S_SM2,S_MD5,S_SM3,S_SM4
from werkzeug.utils import secure_filename
import multiprocessing
import logging
from flask_socketio import SocketIO
from Multithreading import Multi_bruteForce
from MultithreadingOfAES import Multi_bruteForce_16, divide_task_16bit, divide_task
import base64
from threading import Thread
from S_DES_ASCII import S_DES_ASCII
from S_AES_ASCII import S_AES_ASCII
import time
import psutil
import random
import math


app = Flask(__name__)
socketio = SocketIO(app)




######################################### 初始化算法实例 #########################################
aes_cipher = S_AES()
des_cipher = S_DES()
des_cipher_ascii = S_DES_ASCII()
aes_cipher_ascii = S_AES_ASCII()
sm3_cipher = S_SM3()
sm4_cipher = S_SM4()
ecc_cipher = S_ECC()
sm2_cipher = S_SM2()
md5_cipher = S_MD5()


######################################### 临时文件存储路径 #########################################
UPLOAD_FOLDER = './uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

######################################### 设置日志记录 #########################################
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)



######################################### 主页路由 #########################################
@app.route('/')
def index():
    return render_template('index.html')  # 渲染index.html页面



######################################### 工具函数 #########################################
def measure_performance(algorithm, data_size, resource_config):
    # 生成假数据
    data = [1] * int(data_size)  # 用 1 构造简单的测试数据

    # 获取系统资源数据前快照
    initial_memory = psutil.virtual_memory().used / (1024 ** 2)  # 转换为 MB
    initial_cpu = psutil.cpu_percent(interval=None)  # CPU 占用率

    # 记录加密时间
    start_time = time.time()
    encrypted_data = algorithm.Encryption(data)  # 执行加密
    encryption_time = (time.time() - start_time) * 1000  # 转换为毫秒

    # 记录解密时间
    start_time = time.time()
    decrypted_data = algorithm.Decryption(encrypted_data)  # 执行解密
    decryption_time = (time.time() - start_time) * 1000  # 转换为毫秒

    # 获取系统资源数据后快照
    final_memory = psutil.virtual_memory().used / (1024 ** 2)  # 转换为 MB
    final_cpu = psutil.cpu_percent(interval=None)  # CPU 占用率

    # 计算内存和 CPU 使用
    memory_usage = final_memory - initial_memory
    cpu_usage = final_cpu - initial_cpu

    # 返回统计数据
    return {
        "encryption_time": encryption_time,
        "decryption_time": decryption_time,
        "memory_usage": memory_usage,
        "cpu_usage": cpu_usage
    }


# 模拟生成密钥、明文、密文数据
def generate_random_binary_data(length):
    return ''.join([str(random.randint(0, 1)) for _ in range(length)])

# 计算皮尔逊相关性
def calculate_correlation(x, y):
    return np.corrcoef(x, y)[0, 1]


def format_matrix(binary_list, width=4):
    """将二进制列表格式化为指定宽度的矩阵形式，转换为十六进制格式并对齐"""
    hex_matrix = []
    for i in range(0, len(binary_list), width):
        # 提取当前行的 4 个元素
        row = binary_list[i:i + width]
        # 将二进制转换为 16 进制并格式化为 2 位对齐
        hex_row = ' '.join(f'{int("".join(map(str, row[j:j+4])), 2):02X}' for j in range(0, len(row), 4))
        hex_matrix.append(hex_row)
    return hex_matrix

def handle_progress_updates(progress_queue):
    """处理进度更新的后台任务."""
    while True:
        try:
            # 从进度队列中获取进度数据
            progress = progress_queue.get()
            # 发送进度更新给前端
            socketio.emit('progress_update', {'progress': progress})
        except Exception as e:
            logger.error(f"进度更新时遇到错误: {e}")
            break

# 定义暴力破解任务函数
def brute_force_worker(start, end, plaintext, ciphertext, mode, result_queue, progress_queue):
    for guess_key in range(start, end):
        guess_key_bin = format(guess_key, 'b').zfill(16 if mode == 's-aes' else 10)  # 根据模式填充为二进制

        if mode == 's-des':
            # 使用现有的 s-des 加密逻辑
            des_cipher.SetKey([int(x) for x in guess_key_bin])
            guess_cipher = des_cipher.Encryption([int(x) for x in plaintext])
        elif mode == 's-aes':
            # 使用现有的 s-aes 加密逻辑
            aes_cipher.SetKey([int(x) for x in guess_key_bin])
            guess_cipher = aes_cipher.Encryption([int(x) for x in plaintext])
        else:
            raise ValueError("未知的加密模式")

        # 进度报告
        progress_queue.put(guess_key)

        # 如果找到匹配的密文，记录密钥（不退出）
        if ''.join(map(str, guess_cipher)) == ''.join(map(str, ciphertext)):
            result_queue.put(guess_key_bin)  # 找到匹配密钥
            # 不退出，继续查找剩余的密钥

# 分割任务，将搜索空间平均分配给多个进程
def divide_task(threads_num, key_space_size):
    step = key_space_size // threads_num
    task_list = [(i * step, (i + 1) * step) for i in range(threads_num)]
    task_list[-1] = (task_list[-1][0], key_space_size)  # 确保最后一个任务涵盖剩余的空间
    return task_list

# 主暴力破解函数，启动多进程任务并记录破解时间
def run_brute_force(threads_num, plaintext, ciphertext, mode):
    start_time = time.time()  # 记录开始时间
    key_space_size = 2 ** 10 if mode == 's-des' else 2 ** 16  # 假设s-des为10位密钥，s-aes为16位密钥
    task_list = divide_task(threads_num, key_space_size)
    result_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()

    processes = []
    for start, end in task_list:
        p = multiprocessing.Process(target=brute_force_worker, args=(start, end, plaintext, ciphertext, mode, result_queue, progress_queue))
        processes.append(p)
        p.start()

    # 收集进程结果和进度
    found_keys = []
    total_progress = 0
    while any(p.is_alive() for p in processes):
        try:
            progress = progress_queue.get_nowait()
            total_progress += 1
            print(f"Progress: {total_progress}/{key_space_size}")
        except:
            pass
        
        # 检查结果队列是否有匹配密钥
        while not result_queue.empty():
            found_key = result_queue.get()
            found_keys.append(found_key)  # 收集所有找到的密钥

    # 等待所有进程结束
    for p in processes:
        p.join()

    end_time = time.time()  # 记录结束时间
    time_taken = end_time - start_time  # 计算总耗时

    return found_keys, time_taken

def handle_progress_updates(progress_queue):
    """Handle progress updates as a background task."""
    while True:
        try:
            progress = progress_queue.get()
            # Emit progress update to front-end
            socketio.emit('progress_update', {'progress': progress})
        except Exception as e:
            logger.error(f"进度更新时遇到错误: {e}")
            break

# 计算熵
def calculate_entropy(data):
    freq = {}
    for byte in data:
        freq[byte] = freq.get(byte, 0) + 1
    entropy = 0
    for count in freq.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return entropy

# 加密强度分析
def encryption_strength(data):
    # 一个简单的示例：可以根据加密后的数据的复杂度来计算
    strength = sum(bin(x).count('1') for x in data) / len(data) * 100
    return strength

# 密钥敏感性分析（这里是简单示例，实际需要对不同密钥进行测试）
def key_sensitivity_analysis(key, data):
    flipped_key = ''.join('1' if k == '0' else '0' for k in key)
    sensitivity = random.uniform(90, 100)  # 假设敏感性在90-100之间
    return sensitivity

# 模拟的加密算法（假设是AES或DES）
def fake_encryption_algorithm(key, data):
    # 模拟加密，返回加密后的数据
    encrypted_data = [(int(k) ^ int(d)) for k, d in zip(key, data)]
    return encrypted_data

def add_padding(base64_string):
    # Add necessary padding if the length of the Base64 string is not a multiple of 4
    return base64_string + '=' * (-len(base64_string) % 4)

######################################### 路由设置 #########################################

# 加密请求
# 加密请求
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    plaintext = data.get('plaintext')

    # 检查输入数据是否正确
    print(f"Received data: mode={mode}, key={key}, plaintext={plaintext}")

    # 根据模式执行加密操作
    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])  # 使用二进制密钥
        result = aes_cipher.Encryption([int(x) for x in plaintext], with_steps=True)  # 获取每轮加密步骤
        response = {
            "ciphertext": ''.join(map(str, result.get('ciphertext', []))),
            "initial_plaintext": format_matrix(result.get('initial_plaintext', [])),
            "roundKey": result.get('roundKey', []),
            "substitution": [format_matrix(sub) for sub in result.get('substitution', [])],
            "shiftRows": [format_matrix(shift) for shift in result.get('shiftRows', [])],
            "mixColumns": [format_matrix(mix) for mix in result.get('mixColumns', [])]
        }

    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])  # 使用二进制密钥
        result = des_cipher.Encryption([int(x) for x in plaintext], with_steps=True)  # 获取每轮加密步骤
        response = {
            "ciphertext": ''.join(map(str, result.get('ciphertext', []))),
            "initial_plaintext": format_matrix(result.get('initial_plaintext', [])),
            "roundKey": result.get('roundKey', []),
            "substitution": [format_matrix(sub) for sub in result.get('substitution', [])],
            "shiftRows": [format_matrix(shift) for shift in result.get('shiftRows', [])],
            "mixColumns": [format_matrix(mix) for mix in result.get('mixColumns', [])]
        }

    elif mode == 's-sm4':
        sm4_cipher.SetKey(bytes.fromhex(key))  # SM4密钥为十六进制格式
        result = sm4_cipher.Encryption(bytes.fromhex(plaintext))  # 明文也为十六进制格式
        response = {"ciphertext": result.hex()}

    elif mode == 's-sm3':
        result = sm3_cipher.Encryption(plaintext.encode('utf-8'))  # SM3哈希操作
        response = {"hash": result}  # 输出哈希值

    elif mode == 's-md5':
        result = md5_cipher.Encryption(plaintext.encode('utf-8'))  # MD5哈希操作
        response = {"hash": result.hex()}  # 输出哈希值

    elif mode == 's-ecc':
        result = ecc_cipher.sign(plaintext.encode('utf-8'))  # 使用ECC算法进行签名
        response = {"ciphertext": result.hex()}  # 输出签名结果

    elif mode == 's-sm2':
        result = sm2_cipher.sign(plaintext.encode('utf-8'))  # 使用SM2算法进行签名
        response = {"ciphertext": result.hex()}  # 输出签名结果

    else:
        return jsonify({"error": "未知的加密模式"}), 400

    # 打印返回数据，便于调试
    print(f"Response data: {response}")
    return jsonify(response)




# 解密请求
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    ciphertext = data.get('ciphertext')

    # 检查密钥格式
    if not key or not all(c in '01' for c in key):  # 确保密钥为二进制格式
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    # 根据模式执行解密操作
    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])
        decrypted = aes_cipher.Decryption([int(x) for x in ciphertext])

    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        decrypted = des_cipher.Decryption([int(x) for x in ciphertext])

    elif mode == 's-sm4':
        sm4_cipher = S_SM4(bytes.fromhex(key))  # SM4密钥为十六进制格式
        decrypted = sm4_cipher.Decryption(bytes.fromhex(ciphertext))

    else:
        return jsonify({"error": "未知的解密模式或算法不支持解密"}), 400

    # 返回解密结果
    return jsonify({
        "plaintext": decrypted.hex() if isinstance(decrypted, bytes) else ''.join(map(str, decrypted))
    })




@app.route('/encrypt_ascii', methods=['POST'])
def encrypt_ascii():
    data = request.get_json()
    mode = data.get('mode')
    key = data.get('key')
    plaintext = data.get('plaintext')

    # 如果是ASCII模式
    if mode == 's-des':
        des_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置 DES 密钥
        try:
            ciphertext = des_cipher_ascii.Encryption_ASCII(plaintext, des_cipher_ascii.K)
            return jsonify({'ciphertext': ciphertext})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    elif mode == 's-aes':
        aes_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置 AES 密钥
        try:
            ciphertext = aes_cipher_ascii.Encryption_ASCII(plaintext)
            return jsonify({'ciphertext': ciphertext})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    return jsonify({'error': 'Invalid mode or data'}), 400


@app.route('/decrypt_ascii', methods=['POST'])
def decrypt_ascii():
    data = request.get_json()
    mode = data.get('mode')
    key = data.get('key')
    ciphertext = data.get('ciphertext')

    # 如果是ASCII模式
    if mode == 's-des':
        des_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置 DES 密钥
        try:
            plaintext = des_cipher_ascii.Decryption_ASCII(ciphertext, des_cipher_ascii.K)
            return jsonify({'plaintext': plaintext})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    
    elif mode == 's-aes':
        aes_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置 AES 密钥
        try:
            plaintext = aes_cipher_ascii.Decryption_ASCII(ciphertext)
            return jsonify({'plaintext': plaintext})
        except Exception as e:
            return jsonify({'error': str(e)}), 400

    return jsonify({'error': 'Invalid mode or data'}), 400



# 加密文件请求
@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key = request.form['key']
    mode = request.form['mode']

    # 校验密钥是否为有效的二进制字符串
    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    # 根据加密模式验证密钥长度
    if mode == 's-aes' and len(key) != 16:
        return jsonify({"error": "S-AES 密钥必须为16位二进制字符串"}), 400
    if mode == 's-des' and len(key) != 10:
        return jsonify({"error": "S-DES 密钥必须为10位二进制字符串"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # 读取文件内容并将其视为 ASCII 文本
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        return jsonify({"error": "读取文件失败"}), 500

    # 根据加密模式执行加密
    try:
        if mode == 's-aes':
            aes_cipher.SetKey([int(x) for x in key])
            encrypted = aes_cipher.Encryption_ASCII(content)
        elif mode == 's-des':
            des_cipher.SetKey([int(x) for x in key])
            encrypted = des_cipher.Encryption_ASCII(content)
        else:
            return jsonify({"error": "未知的加密模式"}), 400
    except Exception as e:
        logger.error(f"加密失败: {e}")
        return jsonify({"error": "加密失败"}), 500

    # 返回加密结果作为纯文本
    return Response(encrypted, mimetype='text/plain')


# 解密文件请求
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    key = request.form['key']
    mode = request.form['mode']

    # 校验密钥是否为有效的二进制字符串
    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    # 根据解密模式验证密钥长度
    if mode == 's-aes' and len(key) != 16:
        return jsonify({"error": "S-AES 密钥必须为16位二进制字符串"}), 400
    if mode == 's-des' and len(key) != 10:
        return jsonify({"error": "S-DES 密钥必须为10位二进制字符串"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # 读取文件内容并将其视为 ASCII 文本
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
    except Exception as e:
        logger.error(f"读取文件失败: {e}")
        return jsonify({"error": "读取文件失败"}), 500

    # 根据解密模式执行解密
    try:
        if mode == 's-aes':
            aes_cipher.SetKey([int(x) for x in key])
            decrypted = aes_cipher.Decryption_ASCII(content)
        elif mode == 's-des':
            des_cipher.SetKey([int(x) for x in key])
            decrypted = des_cipher.Decryption_ASCII(content)
        else:
            return jsonify({"error": "未知的解密模式"}), 400
    except Exception as e:
        logger.error(f"解密失败: {e}")
        return jsonify({"error": "解密失败"}), 500

    # 返回解密结果作为纯文本
    return Response(decrypted, mimetype='text/plain')


# 明密文对照
@app.route('/compare', methods=['POST'])
def compare():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    plaintext = data.get('plaintext')
    
    logger.info(f"收到明密文对照请求: mode={mode}, key={key}, plaintext={plaintext}")
    
    # 密钥校验
    if not key or not all(c in '01' for c in key):
        logger.error("密钥无效，密钥必须为二进制字符串")
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400
    
    try:
        # 处理明文，可以是字符串或数字
        if plaintext.isdigit():
            plaintext_binary = format(int(plaintext), '08b')  # 将数字转换为8位二进制
            logger.info(f"将数字明文转换为二进制: {plaintext_binary}")
        else:
            # 将字符串转换为二进制字符串
            plaintext_binary = ''.join(format(ord(c), '08b') for c in plaintext)
            logger.info(f"将字符串明文转换为二进制: {plaintext_binary}")
        
        if mode == 's-aes':
            if len(key) != 16:
                logger.error("S-AES 密钥必须为16位二进制字符串")
                return jsonify({"error": "S-AES 密钥必须为16位二进制字符串"}), 400
            aes_cipher.SetKey([int(x) for x in key])
            encrypted = aes_cipher.Encryption([int(x) for x in plaintext_binary])
            ciphertext = ''.join(map(str, encrypted))
            logger.info(f"S-AES 加密结果: {ciphertext}")
        elif mode == 's-des':
            if len(key) != 10:
                logger.error("S-DES 密钥必须为10位二进制字符串")
                return jsonify({"error": "S-DES 密钥必须为10位二进制字符串"}), 400
            des_cipher.SetKey([int(x) for x in key])
            encrypted = des_cipher.Encryption([int(x) for x in plaintext_binary])
            ciphertext = ''.join(map(str, encrypted))
            logger.info(f"S-DES 加密结果: {ciphertext}")
        else:
            logger.error("未知的加密模式")
            return jsonify({"error": "未知的加密模式"}), 400
        
        return jsonify({"ciphertext": ciphertext})
    except Exception as e:
        logger.error(f"明密文对照加密失败: {e}")
        return jsonify({"error": f"加密失败: {str(e)}"}), 500


# Flask接口，用于接收暴力破解请求
@app.route('/brute-force', methods=['POST'])
def brute_force():
    data = request.json
    threads_num = int(data.get('threads', 4))
    plaintext = [int(bit) for bit in data.get('plaintext')]
    ciphertext = [int(bit) for bit in data.get('ciphertext')]
    mode = data.get('mode')  # 's-aes' 或 's-des'

    if not plaintext or not ciphertext or not mode:
        return jsonify({"error": "请输入有效的明文、密文和加密模式"}), 400

    print(f"开始暴力破解: 线程数={threads_num}, 明文={plaintext}, 密文={ciphertext}, 模式={mode}")

    # 启动暴力破解任务
    brute_force_thread = Thread(target=run_brute_force, args=(threads_num, plaintext, ciphertext, mode))
    brute_force_thread.start()
    brute_force_thread.join()

    # 检查结果
    found_keys, time_taken = run_brute_force(threads_num, plaintext, ciphertext, mode)

    if found_keys:
        # 格式化输出
        formatted_keys = []
        for i, key in enumerate(found_keys):
            formatted_key = '[{}]'.format(' '.join(key))
            formatted_keys.append(f"暴力解出的密钥{i+1}是: {formatted_key}")
        
        return jsonify({
            "result": formatted_keys,
            "time_taken": f"破解用时: {time_taken:.2f} 秒"
        })
    else:
        return jsonify({"result": "破解失败，未找到匹配的密钥", "time_taken": f"破解用时: {time_taken:.2f} 秒"})



@app.route('/performance-test', methods=['POST'])
def performance_test():
    content = request.json
    key = content['key']
    data_size = int(content['data_size'])
    plaintext = content['plaintext']
    
    # 自动生成明文数据，假设是二进制数据
    data = [random.randint(0, 1) for _ in range(data_size)]
    
    # 模拟加密和解密过程
    encrypted_data = fake_encryption_algorithm(key, data)
    decrypted_data = fake_encryption_algorithm(key, encrypted_data)

    # 计算各种科研指标
    entropy = calculate_entropy(encrypted_data)
    strength = encryption_strength(encrypted_data)
    key_sensitivity = key_sensitivity_analysis(key, encrypted_data)
    
    performance_data = {
        "encryption_time": 1.23,  # 示例值
        "decryption_time": 1.15,  # 示例值
        "memory_usage": 1.48,  # 示例值
        "cpu_usage": 0.0,  # 示例值
        "entropy": entropy,
        "strength": strength,
        "key_sensitivity": key_sensitivity
    }
    
    return jsonify(performance_data)

@app.route('/test')
def test_page():
    return render_template('test.html')


# ECC/SM2 Signing API
@app.route('/sign', methods=['POST'])
def sign():
    data = request.json
    message = data.get('message')
    
    # Ensure message exists
    if not message:
        return jsonify({"error": "No message provided"}), 400

    # Convert the message string to bytes
    message_bytes = message.encode('utf-8')  # Assuming message is UTF-8 encoded
    mode = data.get('mode')
    print(mode)

    if mode == 's-ecc':
        signature = ecc_cipher.sign(message_bytes)
    elif mode == 's-sm2':
        signature = sm2_cipher.sign(message_bytes)
    else:
        return jsonify({"error": "Invalid algorithm"}), 400

    # Return signature in hex format for ease of representation
    return jsonify({"signature": signature.hex()})



@app.route('/verify', methods=['POST'])
def verify():
    data = request.json
    mode = data.get('mode')
    message = data.get('message').encode('utf-8')

    # 打印消息内容
    print(f"消息: {message}")

    # Correct padding for the signature
    signature_base64 = data.get('signature')

    # 打印签名 (Base64 编码)
    print(f"签名 (Base64 编码): {signature_base64}")

    try:
        # Base64 解码签名
        signature = base64.b64decode(signature_base64)  # add_padding 函数可以是你定义的一个函数
        print(f"签名（解码后）: {signature}")  # 打印解码后的签名

    except Exception as e:
        print(f"签名解码错误: {e}")
        return jsonify({"error": "签名解码错误: " + str(e)}), 400

    if mode == 's-ecc':
        is_valid = ecc_cipher.verify(signature, message)
        print(f"签名验证结果: {is_valid}")
        return jsonify({"valid": is_valid})

    elif mode == 's-sm2':
        is_valid = sm2_cipher.verify(signature, message)
        print(f"签名验证结果: {is_valid}")
        return jsonify({"valid": is_valid})

    return jsonify({"error": "未知的验证模式"}), 400




# 双重加密/解密路由
@app.route('/double-encryption', methods=['POST'])
def double_encryption_decryption():
    data = request.json
    action = data.get('action')  # 'encrypt' or 'decrypt'
    mode = data.get('mode')  # 'double-s-aes' or 'double-s-des'
    key1 = data.get('key1')
    key2 = data.get('key2')
    data_input = data.get('data')  # plaintext or ciphertext

    if not key1 or not key2:
        return jsonify({"error": "需要提供两个密钥"}), 400

    if mode == 'double-s-aes':
        cipher = aes_cipher
        if len(key1) != 16 or len(key2) != 16:
            return jsonify({"error": "双重S-AES加密需要两个16位密钥"}), 400
    elif mode == 'double-s-des':
        cipher = des_cipher
        if len(key1) != 10 or len(key2) != 10:
            return jsonify({"error": "双重S-DES加密需要两个10位密钥"}), 400
    else:
        return jsonify({"error": "未知的加密模式"}), 400

    if action == 'encrypt':
        result = double_encryption(cipher, [int(x) for x in data_input], key1, key2)
        return jsonify({"result": ''.join(map(str, result))})
    elif action == 'decrypt':
        result = double_decryption(cipher, [int(x) for x in data_input], key1, key2)
        return jsonify({"result": ''.join(map(str, result))})
    return jsonify({"error": "未知的操作类型"}), 400

def double_encryption(cipher, plaintext, key1, key2):
    cipher.SetKey([int(x) for x in key1])
    first_round_cipher = cipher.Encryption(plaintext, with_steps=False)
    cipher.SetKey([int(x) for x in key2])
    second_round_cipher = cipher.Encryption(first_round_cipher['ciphertext'], with_steps=False)
    return second_round_cipher['ciphertext']

def double_decryption(cipher, ciphertext, key1, key2):
    cipher.SetKey([int(x) for x in key2])
    first_round_plaintext = cipher.Decryption(ciphertext)
    cipher.SetKey([int(x) for x in key1])
    second_round_plaintext = cipher.Decryption(first_round_plaintext)
    return second_round_plaintext




@app.route('/cbc-encryption', methods=['POST'])
def cbc_encryption():
    data = request.json
    action = data.get('action')  # 'encrypt' or 'decrypt'
    mode = data.get('mode')  # 'cbc-s-aes' or 'cbc-s-des'
    key = data.get('key')  # 密钥
    iv = data.get('iv')  # 初始向量
    data_input = data.get('data')  # 明文/密文

    # 将 IV 和输入数据从字符串转换为位列表
    try:
        iv_bits = [int(x) for x in iv if x in '01']  # 确保 IV 是位列表，且只包含0或1
        iv_bits = pad_iv_to_16_bits(iv_bits)  # 确保 IV 是16位
        print(f"IV Bits (after conversion and padding): {iv_bits}")  # 调试输出
    except ValueError:
        return jsonify({"error": "无效的初始向量(IV)，应为二进制字符串"}), 400

    try:
        # 确保输入数据是整数列表
        data_bits = [int(x) for x in data_input if x in '01']
        print(f"Data Bits (after conversion): {data_bits}")  # 调试输出
    except ValueError:
        return jsonify({"error": "无效的输入数据，应为二进制字符串"}), 400

    try:
        # 将密钥转换为整数列表
        key_bits = [int(x) for x in key if x in '01']  # 确保密钥是二进制字符串
        if len(key_bits) != 16:  # 对于 S-AES 密钥应该是 16 位
            return jsonify({"error": "密钥长度应为16位"}), 400
        print(f"Key Bits (after conversion): {key_bits}")  # 调试输出
    except ValueError:
        return jsonify({"error": "无效的密钥，应为二进制字符串"}), 400

    if len(data_bits) == 0:
        return jsonify({"error": "输入数据不能为空"}), 400

    # 确保输入数据长度为16位的倍数
    if len(data_bits) % 16 != 0:
        return jsonify({"error": "输入数据的长度必须是16位的倍数"}), 400

    # 确保选择了正确的加密模式
    if mode == 'cbc-s-aes':
        cipher = aes_cipher
    elif mode == 'cbc-s-des':
        cipher = des_cipher
    else:
        return jsonify({"error": "未知的CBC加密模式"}), 400

    # 设置初始向量和密钥
    cipher.SetIV(iv_bits)
    cipher.SetKey(key_bits)
    print(f"Set IV and Key in Cipher")  # 调试输出

    if action == 'encrypt':
        # 确保传递的数据为整数
        print(f"Data Bits before encryption: {data_bits}")  # 调试输出
        result = cipher.Encryption_CBC(data_bits)
        print(f"Encryption result: {result}")  # 调试输出
    elif action == 'decrypt':
        print(f"Data Bits before decryption: {data_bits}")  # 调试输出
        result = cipher.Decryption_CBC(data_bits)
        print(f"Decryption result: {result}")  # 调试输出
    else:
        return jsonify({"error": "未知的操作类型"}), 400

    return jsonify({"result": ''.join(map(str, result))})


# IV 补齐函数
def pad_iv_to_16_bits(iv):
    # 如果IV不足16位补0，如果超出16位截断
    if len(iv) < 16:
        iv.extend([0] * (16 - len(iv)))
    return iv[:16]  # 确保IV不超过16位




@app.route('/meet-in-the-middle', methods=['POST'])
def meet_in_the_middle():
    data = request.json
    mode = data.get('mode')  # 'meet-s-aes' or 'meet-s-des'
    plaintext = [int(x) for x in data.get('plaintext')]
    ciphertext = [int(x) for x in data.get('ciphertext')]

    if mode == 'meet-s-aes':
        cipher = aes_cipher
    elif mode == 'meet-s-des':
        cipher = des_cipher
    else:
        return jsonify({"error": "未知的加密模式"}), 400

    # 调用中间相遇攻击函数
    result = perform_meet_in_the_middle_attack(cipher, plaintext, ciphertext)
    
    # 返回结果到前端
    return jsonify({"result": result})


def perform_meet_in_the_middle_attack(cipher, plaintext, ciphertext):
    # 假设密钥空间较小，举例 AES 使用 16 位密钥，DES 使用 10 位密钥
    # 在这里我们假设攻击的是 S-AES
    
    key_space_size = 2 ** 16  # 16 位密钥空间
    
    # 存储从明文加密后的“中间”状态，key1 -> 中间状态
    encryption_dict = {}
    
    # 第一步：对明文进行加密，穷举所有可能的 key1，记录加密后的中间状态
    for key1 in range(key_space_size):
        key1_bin = format(key1, '016b')  # 转换成 16 位二进制字符串
        cipher.SetKey([int(x) for x in key1_bin])  # 使用 key1 设置密钥
        middle_state = cipher.Encryption(plaintext)['ciphertext']  # 记录加密到“中间”状态
        encryption_dict[tuple(middle_state)] = key1_bin  # 以中间状态为键，key1 为值存储
    
    # 第二步：对密文进行解密，穷举所有可能的 key2，检查中间状态是否匹配
    for key2 in range(key_space_size):
        key2_bin = format(key2, '016b')  # 转换成 16 位二进制字符串
        cipher.SetKey([int(x) for x in key2_bin])  # 使用 key2 设置密钥
        middle_state = cipher.Decryption(ciphertext)  # 解密到“中间”状态
        
        # 检查解密到的“中间”状态是否存在于加密过程中遇到的中间状态
        if tuple(middle_state) in encryption_dict:
            key1_found = encryption_dict[tuple(middle_state)]  # 对应的 key1
            return f"成功找到匹配的密钥对: key1={key1_found}, key2={key2_bin}"
    
    return "未找到匹配的密钥对"






# 处理进度更新
if __name__ == '__main__':
    app.run(debug=True)


