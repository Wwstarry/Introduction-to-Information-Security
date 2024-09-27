import multiprocessing
from multiprocessing import Process
import pickle
import logging
from S_AES import S_AES
from S_DES import S_DES
import os


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Multi_bruteForce_16(Process):
    def __init__(self, id, start_point, end_point, P, C, mode, queue, finish_queue, progress_queue, lock, event, trans_queue):
        super().__init__()
        self.id = id
        self.begin = start_point  # Integer key
        self.end = end_point      # Integer key
        self.P_list = [int(x) for x in P]
        self.C_list = [int(x) for x in C]
        self.mode = mode.lower()
        
        # 根据模式初始化加密实例和密钥长度
        if self.mode == 's-aes':
            self.Cipher_E = S_AES()
            self.key_length = 16
        elif self.mode == 's-des':
            self.Cipher_E = S_DES()
            self.key_length = 10
        else:
            raise ValueError(f"Unsupported mode: {mode}")
        
        self.queue = queue
        self.finish_queue = finish_queue
        self.progress_queue = progress_queue
        self.lock = lock
        self.event = event
        self.trans_queue = trans_queue
        self.encryption_list = []
        # self.decryption_list = []  # 如果不需要解密，可以移除

    def run(self):
        try:
            first_time = True
            while first_time or self.begin <= self.end:
                first_time = False
                
                # 将整数密钥转换为二进制列表
                key_format = f'0{self.key_length}b'
                key_as_binary_str = format(self.begin, key_format)
                key_as_binary_list = [int(bit) for bit in key_as_binary_str]

                # 设置密钥
                self.Cipher_E.SetKey(key_as_binary_list)

                # 执行加密
                En = self.Cipher_E.Encryption_Attack(self.P_list)
                # 假设 En 是一个嵌套列表，包含每一步的加密结果
                En_str = ''.join(str(bit) for sublist in En for bit in sublist)

                # 将目标密文转换为字符串
                C_str = ''.join(map(str, self.C_list))
                
                # 调试日志：记录当前尝试的密钥和加密结果
                logger.debug(f"Process {self.id}: Trying key {key_as_binary_str}, Encrypted: {En_str}")

                # 比较加密结果与目标密文
                if En_str == C_str:
                    logger.info(f"Process {self.id}: Found matching key {key_as_binary_str}")
                    self.queue.put([self.id, key_as_binary_str])
                    break

                # 更新进度
                self.progress_queue.put(1)
                self.begin +=1

        except Exception as e:
            logger.error(f"Process {self.id} encountered an error: {e}")

        finally:
            self.finish_queue.put(self.id)
            self.event.set()  # 通知主进程任务完成


# 任务分配函数
def divide_task_16bit(num_segments, mode='s-aes'):
    if mode.lower() == 's-aes':
        start = 0
        end = 2**16 -1  # 16-bit key
    elif mode.lower() == 's-des':
        start = 0
        end = 2**10 -1  # 10-bit key
    else:
        raise ValueError(f"Unsupported mode: {mode}")

    if num_segments <= 0:
        return []
    segment_size = (end - start +1) // num_segments
    segments = []
    current_start = start
    for i in range(num_segments):
        current_end = current_start + segment_size -1
        if i == num_segments -1:
            current_end = end  # 最后一个段到达范围末端
        segments.append((current_start, current_end))
        current_start = current_end +1
    return segments





if __name__ == '__main__':
    file_path1 = 'En.pkl'
    file_path2 = 'De.pkl'

    loaded_data1 = []
    loaded_data2 = []

    # 读取第一个.pkl文件
    with open(file_path1, 'rb') as file1:
        try:
            data1 = pickle.load(file1)
            print(data1)
            print(len(data1))
        except EOFError:
            pass

    # 读取第二个.pkl文件
    all_data2 = []
    with open(file_path2, 'rb') as file2:
        while True:
            try:
                data2 = pickle.load(file2)
                all_data2.append(data2)
            except EOFError:
                break

    for data in all_data2:
        loaded_data2 += data
    print(len(loaded_data2))


