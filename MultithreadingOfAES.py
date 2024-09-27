import pickle
from multiprocessing import Process, Queue, Lock, Event
from S_AES import S_AES
import logging

logger = logging.getLogger(__name__)

class Multi_bruteForce_16(Process):
    def __init__(self, id, start_point, end_point, P, C, Queue, finshQueue, Progress, lock, event, T_Queue):
        super().__init__()
        self.id = id
        self.begin = int(start_point, 2)  # 将二进制字符串转换为整数
        self.end = int(end_point, 2)
        self.P_list = [int(x) for x in P]
        self.C_list = [int(x) for x in C]
        self.Cipher_E = S_AES()
        self.Queue = Queue
        self.finshQueue = finshQueue
        self.PgQueue = Progress
        self.lock = lock
        self.event = event
        self.Trans = T_Queue

    def run(self):
        try:
            for key_int in range(self.begin, self.end + 1):
                key_binary_str = format(key_int, '016b')  # 16-bit AES keys
                key_binary_list = [int(bit) for bit in key_binary_str]
                self.Cipher_E.SetKey(key_binary_list)
                encrypted = self.Cipher_E.Encryption(self.P_list)
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




    def BinaryList2Decimal(self, InputBits: list):
        BinaryString = ''.join(str(bit) for bit in InputBits)
        Decimal = int(BinaryString, 2)
        return Decimal

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

    def binary_search_tuples(self,data, target_value):
        left, right = 0, len(data) - 1
        matching_tuples = []

        while left <= right:
            mid = (left + right) // 2
            if data[mid][1] == target_value:
                matching_tuples.append(data[mid])
                # 继续查找左边的匹配项
                left = mid + 1
            elif data[mid][1] < target_value:
                left = mid + 1
            else:
                right = mid - 1

        return matching_tuples
if __name__=='__main__':

    import pickle

    file_path1 = 'En.pkl'
    file_path2 = 'De.pkl'

    loaded_data1 = []
    loaded_data2 = []

    # 读取第一个.pkl文件的前两行数据
    with open(file_path1, 'rb') as file1:
        data1 = pickle.load(file1)
        print(data1)
        print(len(data1))

    # 存储所有数据的列表
    all_data2 = []

    # 打开.pkl文件以读取数据
    with open(file_path2, 'rb') as file2:
        while True:
            try:
                data2 = pickle.load(file2)
                all_data2.append(data2)
            except EOFError:
                break

    # 打印所有加载的数据
    for data in all_data2:
        loaded_data2 +=data
    print(len(loaded_data2))


