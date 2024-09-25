import multiprocessing
from multiprocessing import Process  # Import Process class explicitly
import pickle
import logging
from S_AES import S_AES  # AES 加密逻辑
from S_DES import S_DES  # DES 加密逻辑


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class Multi_bruteForce_16(Process):
    def __init__(self, id, start_point, end_point, P, C, queue, finish_queue, progress_queue, lock, event, trans_queue):
        super().__init__()
        self.id = id
        self.begin = start_point  # 直接使用整数，而不是将其转换为列表
        self.end = end_point      # 直接使用整数，而不是将其转换为列表
        self.P_list = [int(x) for x in P]
        self.C_list = [int(x) for x in C]
        self.Cipher_E = S_AES()
        self.Cipher_D = S_AES()
        self.queue = queue
        self.finish_queue = finish_queue
        self.progress_queue = progress_queue
        self.lock = lock
        self.event = event
        self.trans_queue = trans_queue  # Ensure this parameter is defined
        self.encryption_list = []
        self.decryption_list = []

    def run(self):
        first_time = True
        while first_time or self.begin <= self.end:
            first_time = False
            try:
                # 将当前整数密钥转换为二进制列表（16位）
                key_as_binary_list = [int(bit) for bit in format(self.begin, '016b')]

                # 加密和解密操作
                self.Cipher_E.SetKey(key_as_binary_list)
                self.Cipher_D.SetKey(key_as_binary_list)
                En = self.Cipher_E.Encryption_Attack(self.P_list)
                De = self.Cipher_D.Decryption_Attack(self.C_list)
                En_str = ''.join(''.join(str(bit) for bit in sublist) for sublist in En)
                De_str = ''.join(''.join(str(bit) for bit in sublist) for sublist in De)

                # 比较密文
                if En_str == ''.join(map(str, self.C_list)):
                    logger.info(f"找到匹配的密钥: {self.Cipher_E.GetKey()}")
                    self.queue.put([self.id, self.Cipher_E.GetKey()])
                    break

                # 更新进度
                self.progress_queue.put(1)  # 模拟进度更新
                self.begin += 1  # 递增密钥整数

            except Exception as e:
                logger.error(f"线程 {self.id} 遇到错误: {e}")
                break

        # 保存加密和解密结果
        with self.lock:
            with open('En.pkl', 'ab') as enc_file, open('De.pkl', 'ab') as dec_file:
                pickle.dump(self.encryption_list, enc_file)
                pickle.dump(self.decryption_list, dec_file)

        self.finish_queue.put(self.id)
        self.event.set()  # 通知主进程任务完成


# 任务分配函数
def divide_task_16bit(num_segments):
    start = 0
    end = 65535  # 16-bit 密钥范围
    if num_segments <= 0:
        return []
    segment_size = (end - start) // num_segments
    segments = []
    current_start = start
    for _ in range(num_segments):
        current_end = current_start + segment_size
        if _ == num_segments - 1:
            current_end = end  # 确保最后一个段到达范围末端
        segments.append((current_start, current_end))
        current_start = current_end + 1
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
