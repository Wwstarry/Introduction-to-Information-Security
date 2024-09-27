from multiprocessing import Process, Queue
from S_DES import S_DES
import logging

logger = logging.getLogger(__name__)

# Multithreading.py（用于 DES）
def divide_task(num_segments):
    start = 0
    end = 1023  # 10-bit DES keys
    if num_segments <= 0:
        return []
    segment_size = (end - start + 1) // num_segments
    segments = []
    current_start = start
    for i in range(num_segments):
        current_end = current_start + segment_size - 1
        if i == num_segments - 1:
            current_end = end  # 确保最后一个段到达范围末端
        start_binary = format(current_start, '010b')
        end_binary = format(current_end, '010b')
        segments.append((start_binary, end_binary))
        current_start = current_end + 1
    return segments

# MultithreadingOfAES.py（用于 AES）
def divide_task_16bit(num_segments):
    start = 0
    end = 65535  # 16-bit AES keys
    if num_segments <= 0:
        return []
    segment_size = (end - start + 1) // num_segments
    segments = []
    current_start = start
    for i in range(num_segments):
        current_end = current_start + segment_size - 1
        if i == num_segments - 1:
            current_end = end  # 确保最后一个段到达范围末端
        start_binary = format(current_start, '016b')
        end_binary = format(current_end, '016b')
        segments.append((start_binary, end_binary))
        current_start = current_end + 1
    return segments


class Multi_bruteForce(Process):
    def __init__(self, id, start_point, end_point, P, C, Queue, finshQueue, Progress, lock, event, T_Queue):
        super().__init__()
        self.id = id
        self.begin = int(start_point, 2)  # 将二进制字符串转换为整数
        self.end = int(end_point, 2)
        self.P_list = [int(x) for x in P]
        self.C_list = [int(x) for x in C]
        self.Cipher = S_DES()
        self.Queue = Queue
        self.finshQueue = finshQueue
        self.PgQueue = Progress
        self.lock = lock
        self.event = event
        self.Trans = T_Queue

    def run(self):
        try:
            for key_int in range(self.begin, self.end + 1):
                key_binary_str = format(key_int, '010b')  # 10-bit DES keys
                key_binary_list = [int(bit) for bit in key_binary_str]
                self.Cipher.SetKey(key_binary_list)
                encrypted = self.Cipher.Encryption(self.P_list)
                encrypted_str = ''.join(map(str, encrypted))
                target_str = ''.join(map(str, self.C_list))
                if encrypted_str == target_str:
                    logger.info(f"Process {self.id}: Found key {key_binary_str}")
                    self.Queue.put([self.id, key_binary_str])
                    break
                self.PgQueue.put(1)
        except Exception as e:
            logger.error(f"Process {self.id} encountered an error: {e}")
        finally:
            self.finshQueue.put(self.id)
            self.event.set()

    def binary_addition(self, bin_list1, bin_list2):
        max_len = max(len(bin_list1), len(bin_list2))
        bin_list1 = [0] * (max_len - len(bin_list1)) + bin_list1
        bin_list2 = [0] * (max_len - len(bin_list2)) + bin_list2

        result = []
        carry = 0

        for i in range(max_len - 1, -1, -1):
            bit1 = bin_list1[i]
            bit2 = bin_list2[i]

            # 计算当前位的和，考虑进位
            bit_sum = bit1 + bit2 + carry
            result.insert(0, bit_sum % 2)
            carry = bit_sum // 2

        if carry:
            result.insert(0, 1)

        return result
