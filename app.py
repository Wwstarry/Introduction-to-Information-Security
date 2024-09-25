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

app = Flask(__name__)

# 初始化 AES 和 DES 算法实例
aes_cipher = S_AES()
des_cipher = S_DES()

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

    # 将加密结果转为字符串返回
    encrypted_str = ''.join(map(str, encrypted))
    return jsonify({"ciphertext": encrypted_str})


# 解密请求
@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    mode = data.get('mode')
    key = data.get('key')
    ciphertext = data.get('ciphertext')

    # 密钥校验
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


# 文件加密
@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key = request.form['key']
    mode = request.form['mode']

    # 密钥校验
    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    # 保存文件并读取内容
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # 以文本模式读取文件内容并将其转换为二进制字符串
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 将文件内容转换为二进制字符串
    content_as_binary = ''.join(format(ord(char), '08b') for char in content)

    # 根据加密模式执行加密
    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])
        encrypted = aes_cipher.Encryption([int(x) for x in content_as_binary])
    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        encrypted = des_cipher.Encryption([int(x) for x in content_as_binary])
    else:
        return jsonify({"error": "未知的加密模式"}), 400

    # 将加密内容转为字符串返回
    encrypted_str = ''.join(map(str, encrypted))
    return encrypted_str


# 文件解密
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file():
    file = request.files['file']
    key = request.form['key']
    mode = request.form['mode']

    # 密钥校验
    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    # 保存文件并读取内容
    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    # 以文本模式读取文件内容
    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    # 解密之前，将文件内容转换为二进制数值
    content_as_binary = ''.join(format(ord(char), '08b') for char in content)

    # 根据解密模式执行解密
    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])
        decrypted = aes_cipher.Decryption([int(x) for x in content_as_binary])
    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        decrypted = des_cipher.Decryption([int(x) for x in content_as_binary])
    else:
        return jsonify({"error": "未知的解密模式"}), 400

    # 将解密后的二进制数据转换回字符
    decrypted_chars = [chr(int(''.join(map(str, decrypted[i:i + 8])), 2)) for i in range(0, len(decrypted), 8)]

    decrypted_str = ''.join(decrypted_chars)
    return decrypted_str


from flask import Flask, request, jsonify, render_template
import os
from S_AES import S_AES  # AES 加密逻辑
from S_DES import S_DES  # DES 加密逻辑
from werkzeug.utils import secure_filename
import multiprocessing
import logging
from flask_socketio import SocketIO
from multi_brute_force import Multi_bruteForce_16, divide_task_16bit

app = Flask(__name__)
socketio = SocketIO(app)

# 初始化 AES 和 DES 算法实例
aes_cipher = S_AES()
des_cipher = S_DES()

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

# 文件加密
@app.route('/encrypt-file', methods=['POST'])
def encrypt_file():
    file = request.files['file']
    key = request.form['key']
    mode = request.form['mode']

    if not key or not all(c in '01' for c in key):
        return jsonify({"error": "密钥无效，密钥必须为二进制字符串"}), 400

    filename = secure_filename(file.filename)
    filepath = os.path.join(UPLOAD_FOLDER, filename)
    file.save(filepath)

    with open(filepath, 'r', encoding='utf-8') as f:
        content = f.read()

    content_as_binary = ''.join(format(ord(char), '08b') for char in content)

    if mode == 's-aes':
        aes_cipher.SetKey([int(x) for x in key])
        encrypted = aes_cipher.Encryption([int(x) for x in content_as_binary])
    elif mode == 's-des':
        des_cipher.SetKey([int(x) for x in key])
        encrypted = des_cipher.Encryption([int(x) for x in content_as_binary])
    else:
        return jsonify({"error": "未知的加密模式"}), 400

    encrypted_str = ''.join(map(str, encrypted))
    return encrypted_str

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


# 暴力破解请求
@app.route('/brute-force', methods=['POST'])
def brute_force():
    data = request.json
    threads = int(data.get('threads', 4))
    plaintext = data.get('plaintext')
    ciphertext = data.get('ciphertext')

    if not plaintext or not ciphertext:
        return jsonify({"error": "请输入有效的明文和密文"}), 400

    logger.info(f"开始暴力破解: 线程数={threads}, 明文={plaintext}, 密文={ciphertext}")

    task_list = divide_task_16bit(threads)

    queue = multiprocessing.Queue()
    finish_queue = multiprocessing.Queue()
    progress_queue = multiprocessing.Queue()
    lock = multiprocessing.Lock()
    event = multiprocessing.Event()
    trans_queue = multiprocessing.Queue()

    processes = []
    for i in range(threads):
        p = Multi_bruteForce_16(
            id=i,
            start_point=task_list[i][0],
            end_point=task_list[i][1],
            P=plaintext,
            C=ciphertext,
            queue=queue,
            finish_queue=finish_queue,
            progress_queue=progress_queue,
            lock=lock,
            event=event,
            trans_queue=trans_queue
        )
        processes.append(p)
        p.start()

    socketio.start_background_task(handle_progress_updates, progress_queue)

    for p in processes:
        p.join()

    if not queue.empty():
        found_key = queue.get()
        logger.info(f"暴力破解成功，找到密钥: {found_key}")
        socketio.emit('key_found', {'key': found_key})
        return jsonify({"result": f"破解成功，找到的密钥为: {found_key}"})
    else:
        logger.info("暴力破解失败，未找到匹配的密钥")
        return jsonify({"result": "破解失败，未找到匹配的密钥"})

# 处理进度更新
if __name__ == '__main__':
    app.run(debug=True)
