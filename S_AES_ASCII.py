import gf  # 假设你有一个 Galois Field (GF) 实现的库

class S_AES_ASCII:
    def __init__(self):
        self.gf = gf.GF(4)  # Galois field for AES
        self.K = []
        self.w = [[], [], [], [], [], []]
        self.NS = [[9, 4, 0xA, 0xB], [0xD, 1, 8, 5], [6, 2, 0, 3], [0xC, 0xE, 0xF, 7]]
        self.INS = [[0xA, 5, 9, 0xB], [1, 7, 8, 0xF], [6, 0, 2, 3], [0xC, 4, 0xD, 0xE]]
        self.RC = [[1, 0, 0, 0, 0, 0, 0, 0], [0, 0, 1, 1, 0, 0, 0, 0]]
        self.MC = [[1, 4], [4, 1]]
        self.IMC = [[9, 2], [2, 9]]
        self.IV = []

    def SetKey(self, InputBits: list):
        """设置密钥"""
        self.K = InputBits
        self.w[0] = self.K[0:8]
        self.w[1] = self.K[8:16]
        self.w[2] = self.XOR(self.w[0], self.gFunction(self.w[1], 1))
        self.w[3] = self.XOR(self.w[2], self.w[1])
        self.w[4] = self.XOR(self.w[2], self.gFunction(self.w[3], 2))
        self.w[5] = self.XOR(self.w[4], self.w[3])

    def Encryption(self, InputBits, with_steps=False):
        """执行 AES 加密"""
        Pre_Trans = self.XOR(InputBits, self.w[0] + self.w[1])
        Sub_Trans = self.Nibble_Substitution(Pre_Trans, self.NS)
        Shift_Trans = self.ShiftRows(Sub_Trans)
        MC_Trans = self.MixColumns(Shift_Trans, self.MC)
        Pre_Trans_2 = self.XOR(MC_Trans, self.w[2] + self.w[3])
        Sub_Trans_2 = self.Nibble_Substitution(Pre_Trans_2, self.NS)
        Shift_Trans_2 = self.ShiftRows(Sub_Trans_2)
        Pre_Trans_3 = self.XOR(Shift_Trans_2, self.w[4] + self.w[5])
        return Pre_Trans_3

    def Decryption(self, InputBits):
        """执行 AES 解密"""
        Pre_Trans = self.XOR(InputBits, self.w[4] + self.w[5])
        Shift_Trans = self.ShiftRows(Pre_Trans)
        Sub_Trans = self.Nibble_Substitution(Shift_Trans, self.INS)
        Pre_Trans_2 = self.XOR(Sub_Trans, self.w[2] + self.w[3])
        MC_Trans = self.MixColumns(Pre_Trans_2, self.IMC)
        Shift_Trans_2 = self.ShiftRows(MC_Trans)
        Sub_Trans_2 = self.Nibble_Substitution(Shift_Trans_2, self.INS)
        Pre_Trans_3 = self.XOR(Sub_Trans_2, self.w[0] + self.w[1])
        return Pre_Trans_3

    def ascii_to_binary(self, text: str) -> list:
        """将 ASCII 文本转换为二进制"""
        binary_list = []
        for char in text:
            binary_char = format(ord(char), '08b')
            binary_list.extend([int(bit) for bit in binary_char])
        return binary_list

    def binary_to_ascii(self, binary_list: list) -> str:
        """将二进制转换回 ASCII 文本"""
        chars = []
        for i in range(0, len(binary_list), 8):
            byte = binary_list[i:i + 8]
            char_code = int(''.join(map(str, byte)), 2)
            chars.append(chr(char_code))
        return ''.join(chars)

    def binary_to_garbage(self, binary_list: list) -> str:
        """将二进制转换为乱码字符"""
        garbage_chars = []
        for i in range(0, len(binary_list), 8):
            byte = binary_list[i:i + 8]
            byte_value = int(''.join(map(str, byte)), 2)
            garbage_chars.append(chr(byte_value))
        return ''.join(garbage_chars)

    def garbage_to_binary(self, garbage_str: str) -> list:
        """将乱码字符转换回二进制"""
        binary_list = []
        for char in garbage_str:
            binary_char = format(ord(char), '08b')
            binary_list.extend([int(bit) for bit in binary_char])
        return binary_list

    def Encryption_ASCII(self, plaintext: str) -> str:
        """加密 ASCII 文本并返回乱码"""
        binary_plaintext = self.ascii_to_binary(plaintext)
        encrypted_binary = self.Encryption(binary_plaintext)
        return self.binary_to_garbage(encrypted_binary)

    def Decryption_ASCII(self, ciphertext: str) -> str:
        """解密乱码字符并恢复为明文"""
        binary_ciphertext = self.garbage_to_binary(ciphertext)
        decrypted_binary = self.Decryption(binary_ciphertext)
        return self.binary_to_ascii(decrypted_binary)

    def XOR(self, list1, list2):
        """按位异或"""
        return [bit1 ^ bit2 for bit1, bit2 in zip(list1, list2)]

    def Nibble_Substitution(self, InputBits, SubstitutionBox):
        """半字节替换"""
        S00 = InputBits[0:4]
        S10 = InputBits[4:8]
        S01 = InputBits[8:12]
        S11 = InputBits[12:16]
        S_S00 = self.SBox(S00, SubstitutionBox)
        S_S10 = self.SBox(S10, SubstitutionBox)
        S_S01 = self.SBox(S01, SubstitutionBox)
        S_S11 = self.SBox(S11, SubstitutionBox)
        return S_S00 + S_S10 + S_S01 + S_S11

    def ShiftRows(self, InputBits):
        """行位移"""
        S00 = InputBits[0:4]
        S10 = InputBits[4:8]
        S01 = InputBits[8:12]
        S11 = InputBits[12:16]
        return S00 + S11 + S01 + S10

    def MixColumns(self, InputBits, Matrix):
        """列混淆"""
        S00 = InputBits[0:4]
        S10 = InputBits[4:8]
        S01 = InputBits[8:12]
        S11 = InputBits[12:16]
        S00 = self.BinaryList2Decimal(S00)
        S10 = self.BinaryList2Decimal(S10)
        S01 = self.BinaryList2Decimal(S01)
        S11 = self.BinaryList2Decimal(S11)
        Dec_MC_Trans = self.matrix_multiply(Matrix, [[S00, S01], [S10, S11]])
        MC_Trans = []
        for row in Dec_MC_Trans:
            for element in row:
                MC_Trans.append(self.Decimal2BinaryList(element))
        return [item for sublist in MC_Trans for item in sublist]

    def matrix_multiply(self, A, B):
        rows_A = len(A)
        cols_B = len(B[0])
        C = [[0] * cols_B for _ in range(rows_A)]
        for i in range(rows_A):
            for j in range(cols_B):
                for k in range(len(A[0])):
                    C[i][j] = self.gf.add(C[i][j], self.gf.mul(A[i][k], B[k][j]))
        return C

    def BinaryList2Decimal(self, InputBits: list):
        """将二进制列表转换为十进制"""
        return int(''.join(map(str, InputBits)), 2)

    def Decimal2BinaryList(self, Number: int):
        """将十进制数字转换为二进制列表"""
        BinaryString = bin(Number)[2:].zfill(4)
        return [int(bit) for bit in BinaryString]

    def SBox(self, InputBits, SubstitutionBox):
        """S盒子操作"""
        Row = self.BinaryList2Decimal([InputBits[0], InputBits[3]])
        Column = self.BinaryList2Decimal([InputBits[1], InputBits[2]])
        return self.Decimal2BinaryList(SubstitutionBox[Row][Column])

if __name__ == "__main__":
    aes_machine = S_AES_ASCII()
    aes_machine.SetKey([0, 1, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1, 1])
    
    # 测试 ASCII 加密
    plaintext = "Hello"
    print(f"明文: {plaintext}")
    
    encrypted = aes_machine.Encryption_ASCII(plaintext)
    print(f"加密后的乱码: {encrypted}")
    
    decrypted = aes_machine.Decryption_ASCII(encrypted)
    print(f"解密后的明文: {decrypted}")
