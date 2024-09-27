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
def run_brute_force(threads_num, plaintext, ciphertext, mode, queue, finish_queue, progress_queue, lock, event, trans_queue):
    if mode == 's-aes':
        task_list = divide_task_16bit(threads_num)
        processes = []
        for i in range(threads_num):
            p = Multi_bruteForce_16(
                id=i,
                start_point=task_list[i][0],
                end_point=task_list[i][1],
                P=plaintext,
                C=ciphertext,
                Queue=queue,
                finshQueue=finish_queue,
                Progress=progress_queue,
                lock=lock,
                event=event,
                T_Queue=trans_queue
            )
            processes.append(p)
            p.start()
            logger.info(f"Process:{i} 已启动")
    elif mode == 's-des':
        task_list = divide_task(threads_num)
        processes = []
        for i in range(threads_num):
            p = Multi_bruteForce(
                id=i,
                start_point=task_list[i][0],
                end_point=task_list[i][1],
                P=plaintext,
                C=ciphertext,
                Queue=queue,
                finshQueue=finish_queue,
                Progress=progress_queue,
                lock=lock,
                event=event,
                T_Queue=trans_queue
            )
            processes.append(p)
            p.start()
            logger.info(f"Process:{i} 已启动")
    else:
        logger.error("未知的加密模式")
        return

    # Start background task to handle progress updates
    socketio.start_background_task(handle_progress_updates, progress_queue)

    # Wait for all processes to finish
    for p in processes:
        p.join()

    # Collect results
    results = []
    while not queue.empty():
        results.append(queue.get())

    if results:
        keys = [result[1] for result in results]
        logger.info(f"暴力破解成功，找到密钥: {keys}")
        socketio.emit('key_found', {'key': keys})
    else:
        logger.info("暴力破解失败，未找到匹配的密钥")
        socketio.emit('key_found', {'key': []})


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


@app.route('/brute-force', methods=['POST'])
def brute_force():
    data = request.json
    threads_num = int(data.get('threads', 4))
    plaintext = data.get('plaintext')
    ciphertext = data.get('ciphertext')
    mode = data.get('mode')  # 's-aes' 或 's-des'

    if not plaintext or not ciphertext or not mode:
        return jsonify({"error": "请输入有效的明文、密文和加密模式"}), 400

    logger.info(f"开始暴力破解: 线程数={threads_num}, 明文={plaintext}, 密文={ciphertext}, 模式={mode}")

    # 初始化 multiprocessing Manager 和 Queues
    manager = multiprocessing.Manager()
    queue = manager.Queue()
    finish_queue = manager.Queue()
    progress_queue = manager.Queue()
    lock = manager.Lock()
    event = manager.Event()
    trans_queue = manager.Queue()

    # 定义暴力破解任务
    def run_brute_force():
        if mode == 's-aes':
            task_list = divide_task_16bit(threads_num)
            processes = []
            for i in range(threads_num):
                p = Multi_bruteForce_16(
                    id=i,
                    start_point=task_list[i][0],
                    end_point=task_list[i][1],
                    P=plaintext,
                    C=ciphertext,
                    Queue=queue,
                    finshQueue=finish_queue,
                    Progress=progress_queue,
                    lock=lock,
                    event=event,
                    T_Queue=trans_queue
                )
                processes.append(p)
                p.start()
                logger.info(f"Process:{i} 已启动")
        elif mode == 's-des':
            task_list = divide_task(threads_num)
            processes = []
            for i in range(threads_num):
                p = Multi_bruteForce(
                    id=i,
                    start_point=task_list[i][0],
                    end_point=task_list[i][1],
                    P=plaintext,
                    C=ciphertext,
                    Queue=queue,
                    finshQueue=finish_queue,
                    Progress=progress_queue,
                    lock=lock,
                    event=event,
                    T_Queue=trans_queue
                )
                processes.append(p)
                p.start()
                logger.info(f"Process:{i} 已启动")
        else:
            logger.error("未知的加密模式")
            return

        # 等待所有进程完成
        for p in processes:
            p.join()

    # 启动暴力破解任务在一个独立的线程中，避免阻塞 Flask 主线程
    brute_force_thread = Thread(target=run_brute_force)
    brute_force_thread.start()
    brute_force_thread.join()  # 等待暴力破解完成

    # 收集结果
    results = []
    while not queue.empty():
        results.append(queue.get())

    if results:
        # 假设可能找到多个密钥
        keys = [result[1] for result in results]
        logger.info(f"暴力破解成功，找到密钥: {keys}")
        return jsonify({"result": keys})
    else:
        logger.info("暴力破解失败，未找到匹配的密钥")
        return jsonify({"result": "破解失败，未找到匹配的密钥"})

# 处理进度更新
if __name__ == '__main__':
    app.run(debug=True)

# if __name__ == '__main__':
#     socketio.run(app, debug=True)
