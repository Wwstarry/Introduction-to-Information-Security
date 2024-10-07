from flask import Flask, request, jsonify, render_template, Response
import os
from S_AES import S_AES
from S_DES import S_DES
from werkzeug.utils import secure_filename
import multiprocessing
import logging
from flask_socketio import SocketIO
from Multithreading import Multi_bruteForce
from MultithreadingOfAES import Multi_bruteForce_16, divide_task_16bit, divide_task
import base64
from threading import Thread
from S_DES_ASCII import S_DES_ASCII
import time

app = Flask(__name__)
socketio = SocketIO(app)

# 初始化 AES 和 DES 算法实例
aes_cipher = S_AES()
des_cipher = S_DES()
# 初始化 S_DES 实例
des_cipher_ascii = S_DES_ASCII()

# 临时文件存储路径
UPLOAD_FOLDER = './uploads'
if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

# 设置日志记录
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

@app.route('/')
def index():
    return render_template('index.html')  # 渲染index.html页面

# 加密请求
@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    plaintext = data.get('plaintext')

    # 密钥校验
    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])  # 设置密钥
        encrypted = aes_cipher.Encryption([int(x) for x in plaintext])  # 执行加密
    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        encrypted = des_cipher.Encryption([int(x) for x in plaintext])
    else:
        return jsonify({"error": "未知的加密模式"}), 400

    encrypted_str = ''.join(map(str, encrypted))
    return jsonify({"ciphertext": encrypted_str})

# 解密请求
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    ciphertext = data.get('ciphertext')

    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])
        decrypted = aes_cipher.Decryption([int(x) for x in ciphertext])
    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        decrypted = des_cipher.Decryption([int(x) for x in ciphertext])
    else:
        return jsonify({"error": "未知的解密模式"}), 400

    decrypted_str = ''.join(map(str, decrypted))
    return jsonify({"plaintext": decrypted_str})

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


@app.route('/encrypt_ascii', methods=['POST'])
def encrypt_ascii():
    data = request.get_json()
    mode = data.get('mode')
    key = data.get('key')
    plaintext = data.get('plaintext')

    # 如果是ASCII模式
    if mode == 's-des':
        des_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置密钥
        try:
            ciphertext = des_cipher_ascii.Encryption_ASCII(plaintext, des_cipher_ascii.K)
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
        des_cipher_ascii.SetKey([int(bit) for bit in key])  # 设置密钥
        try:
            plaintext = des_cipher_ascii.Decryption_ASCII(ciphertext, des_cipher_ascii.K)
            return jsonify({'plaintext': plaintext})
        except Exception as e:
            return jsonify({'error': str(e)}), 400
    return jsonify({'error': 'Invalid mode or data'}), 400













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


# 处理进度更新
if __name__ == '__main__':
    app.run(debug=True)

# if __name__ == '__main__':
#     socketio.run(app, debug=True)
