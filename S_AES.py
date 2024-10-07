import gf


class S_AES():


    def SetIV(self, InputList: list):
        self.IV = InputList

    def GetIV(self):
        return ''.join(map(str, self.IV))

    def __init__(self):
        self.gf = gf.GF(4)
        self.K = []
        self.w = [[], [], [], [], [], []]
        self.NS = [[9, 4, 0xA, 0xB],
              [0xD, 1, 8, 5],
              [6, 2, 0, 3],
              [0xC, 0xE, 0xF, 7]]

        self.INS = [[0xA, 5, 9, 0xB],
               [1, 7, 8, 0xF],
               [6, 0, 2, 3],
               [0xC, 4, 0xD, 0xE]]

        self.RC = [[1, 0, 0, 0, 0, 0, 0, 0],
              [0, 0, 1, 1, 0, 0, 0, 0]]
        self.MC = [[1, 4],
              [4, 1]]
        self.IMC = [[9, 2],
               [2, 9]]
        self.IV = []


    def Encryption(self, InputBits, with_steps=False):
        """应提供16bit的明文进行加密操作，并且根据需要返回每一步骤的中间结果"""

        # 初始化字典，用来存储各步骤的结果
        result = {
            "initial_plaintext": InputBits,  # 初始输入
            "substitution": [],              # 存储半字节替换的结果
            "shiftRows": [],                 # 存储行位移的结果
            "mixColumns": [],                # 存储列混淆的结果
            "ciphertext": []                 # 最终的密文
        }

        # 第一步：加轮变换
        Pre_Trans = self.XOR(InputBits, self.w[0] + self.w[1])  # 执行加轮变换

        # 第二步：半字节替换
        Sub_Trans = self.Nibble_Substitution(Pre_Trans, self.NS)  # 半字节替换
        if with_steps:
            result["substitution"].append(Sub_Trans)  # 记录第一轮半字节替换的结果

        # 第三步：行位移
        Shift_Trans = self.ShiftRows(Sub_Trans)  # 行位移
        if with_steps:
            result["shiftRows"].append(Shift_Trans)  # 记录第一轮行位移的结果

        # 第四步：列混淆
        MC_Trans = self.MixColumns(Shift_Trans, self.MC)  # 列混淆
        if with_steps:
            result["mixColumns"].append(MC_Trans)  # 记录第一轮列混淆的结果

        # 第五步：加轮变换
        Pre_Trans_2 = self.XOR(MC_Trans, self.w[2] + self.w[3])

        # 第六步：半字节替换（第二轮）
        Sub_Trans_2 = self.Nibble_Substitution(Pre_Trans_2, self.NS)  # 第二轮半字节替换
        if with_steps:
            result["substitution"].append(Sub_Trans_2)  # 记录第二轮半字节替换的结果

        # 第七步：行位移（第二轮）
        Shift_Trans_2 = self.ShiftRows(Sub_Trans_2)  # 第二轮行位移
        if with_steps:
            result["shiftRows"].append(Shift_Trans_2)  # 记录第二轮行位移的结果

        # 第八步：加轮变换（最后一步）
        Pre_Trans_3 = self.XOR(Shift_Trans_2, self.w[4] + self.w[5])
        result["ciphertext"] = Pre_Trans_3  # 最终的密文

        # 返回包含所有步骤结果的字典
        return result
    



    def Decryption(self, InputBits):
        """应该给出16bit的明文。进行加密操作"""
        Pre_Trans = self.XOR(InputBits, self.w[4] + self.w[5])  # 加轮变换
        Shift_Trans = self.ShiftRows(Pre_Trans)  # 逆行位移，在该情景下，逆行变换和行变换相同
        Sub_Trans = self.Nibble_Substitution(Shift_Trans, self.INS)  # 逆半字节替换
        Pre_Trans_2 = self.XOR(Sub_Trans, self.w[2] + self.w[3])
        MC_Trans = self.MixColumns(Pre_Trans_2, self.IMC)  # 逆列混淆
        Shift_Trans_2 = self.ShiftRows(MC_Trans)  # 逆行位移
        Sub_Trans_2 = self.Nibble_Substitution(Shift_Trans_2, self.INS)  # 逆半字节替换
        Pre_Trans_3 = self.XOR(Sub_Trans_2, self.w[0] + self.w[1])  # 加轮变换
        return Pre_Trans_3

    def Nibble_Substitution(self, InputBits, SubstitutionBox):
        """半字节替换函数，给定16bit以及替换盒子，返回16bit列表"""
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
        """行位移，把第二行的进行半字节循环位移"""
        S00 = InputBits[0:4]
        S10 = InputBits[4:8]
        S01 = InputBits[8:12]
        S11 = InputBits[12:16]
        return S00 + S11 + S01 + S10

    def MixColumns(self, InputBits, Matrix):
        S00 = InputBits[0:4]
        S10 = InputBits[4:8]
        S01 = InputBits[8:12]
        S11 = InputBits[12:16]
        S00 = self.BinaryList2Decimal(S00)
        S10 = self.BinaryList2Decimal(S10)
        S01 = self.BinaryList2Decimal(S01)
        S11 = self.BinaryList2Decimal(S11)
        Dec_MC_Trans = self.matrix_multiply(Matrix, [[S00, S01],
                                                     [S10, S11]])
        MC_Trans = []
        for i in range(len(Dec_MC_Trans)):
            for j in range(len(Dec_MC_Trans)):
                MC_Trans.append(self.Decimal2BinaryList(Dec_MC_Trans[j][i]))

        MC_Trans = [element for row in MC_Trans for element in row]

        return MC_Trans

    def matrix_multiply(self, A, B):
        rows_A = len(A)
        cols_A = len(A[0])
        rows_B = len(B)
        cols_B = len(B[0])
        C = [[0] * cols_B for _ in range(rows_A)]
        for i in range(rows_A):
            for j in range(cols_B):
                for k in range(cols_A):
                    C[i][j] = self.gf.add(C[i][j], self.gf.mul(A[i][k], B[k][j]))
        return C

    def XOR(self, list1, list2):
        return [bit1 ^ bit2 for bit1, bit2 in zip(list1, list2)]

    def SetKey(self, InputBits: list):
        """密钥设定"""
        self.K = InputBits
        self.w[0] = self.K[0:8]
        self.w[1] = self.K[8:16]  # 左闭右开
        self.w[2] = self.XOR(self.w[0], self.gFunction(self.w[1], 1))
        self.w[3] = self.XOR(self.w[2], self.w[1])
        self.w[4] = self.XOR(self.w[2], self.gFunction(self.w[3], 2))
        self.w[5] = self.XOR(self.w[4], self.w[3])

    def gFunction(self, InputBits: list, index):
        """给定一个8bit，返回其g变换结果，包含S变换和加轮密钥"""
        N1 = InputBits[-4:]
        N0 = InputBits[:4]
        _N1 = self.SBox(N1, self.NS)
        _N0 = self.SBox(N0, self.NS)
        return self.XOR(_N1 + _N0, self.RC[index - 1])

    def BinaryList2Decimal(self, InputBits: list):
        BinaryString = ''.join(str(bit) for bit in InputBits)
        Decimal = int(BinaryString, 2)
        return Decimal

    def Decimal2BinaryList(self, Number: int):
        BinaryString = bin(Number)
        BinaryList = [int(x) for x in BinaryString[2:]]
        while len(BinaryList) < 4:
            BinaryList.insert(0, 0)
        return BinaryList

    def SBox(self, InputBits, SubstitutionBox):
        # 混淆盒，需要用列表的形式传入4bit数据，并且给定二维数组混淆表
        RowBinary = [InputBits[0], InputBits[1]]
        ColumnBinary = [InputBits[2], InputBits[3]]
        Row = self.BinaryList2Decimal(RowBinary)
        Column = self.BinaryList2Decimal(ColumnBinary)
        return self.Decimal2BinaryList(SubstitutionBox[Row][Column])

    def GetKey(self):
        return ''.join(map(str, self.K))
    def Encryption_CBC(self,InputList:list):
        """输入一个完整字符串的Bit进行加密"""
        if len(InputList)==0:
            return []
        result=[]
        P = InputList[:16]
        print(P)

        Last_Vector = self.Encryption(self.XOR(self.IV, P))
        result.append([x for x in Last_Vector])

        for i in range(16,len(InputList),16):
            P=InputList[i:i+16]
            Last_Vector = self.Encryption(self.XOR(Last_Vector, P))
            result.append([x for x in Last_Vector])

        flattened_result = [element for sublist in result for element in sublist]
        return flattened_result

    def Decryption_CBC(self,InputList:list):
        """输入一个完整加密字符串的Bit进行解密"""
        if len(InputList)==0:
            return []
        result = []
        C = InputList[:16]
        Last_Vector=self.Decryption(C)
        P=self.XOR(self.IV, Last_Vector)

        result.append([x for x in P])

        for i in range(16, len(InputList), 16):
            C = InputList[i:i+16]
            Last_Vector = self.Decryption(C)
            P = self.XOR(InputList[i-16:i], Last_Vector)
            result.append([x for x in P])

        flattened_result = [element for sublist in result for element in sublist]
        return flattened_result

    def Encryption_Attack(self,InputList:list):
        result=[]
        for i in range(0,len(InputList),16):
            P=InputList[i:i+16]
            En = self.Encryption(P)
            result.append(En)
        return result
    def Decryption_Attack(self,InputList:list):
        result=[]
        for i in range(0,len(InputList),16):
            C=InputList[i:i+16]
            De = self.Decryption(C)
            result.append(De)
        return result
    
    def ascii_to_binary(self, text: str) -> list:
        """将ASCII字符串转换为二进制列表"""
        binary_list = []
        for char in text:
            # 将每个字符的ASCII码转换为8位二进制
            binary_char = format(ord(char), '08b')
            binary_list.extend([int(bit) for bit in binary_char])
        return binary_list

    def binary_to_ascii(self, binary_list: list) -> str:
        """将二进制列表转换回ASCII字符串"""
        chars = []
        for i in range(0, len(binary_list), 8):
            # 每8个二进制位转换为一个字符
            byte = binary_list[i:i+8]
            char_code = int(''.join(map(str, byte)), 2)
            chars.append(chr(char_code))
        return ''.join(chars)
    
    def Encryption_ASCII(self, plaintext: str) -> str:
        """将ASCII明文加密"""
        binary_plaintext = self.ascii_to_binary(plaintext)
        # 执行加密
        encrypted_binary = self.Encryption(binary_plaintext)
        # 将加密后的二进制转换回ASCII表示
        return self.binary_to_ascii(encrypted_binary)

    def Decryption_ASCII(self, ciphertext: str) -> str:
        """将加密的ASCII密文解密"""
        binary_ciphertext = self.ascii_to_binary(ciphertext)
        # 执行解密
        decrypted_binary = self.Decryption(binary_ciphertext)
        # 将解密后的二进制转换回ASCII表示
        return self.binary_to_ascii(decrypted_binary)

if __name__ == "__main__":
    a_E = S_AES()
    a_D = S_AES()



    value=[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1]

    value2=[0,1,0,0,1,0,0,0,0,0,0,0,1,1,1,0]

    a_D.SetKey([0,0,1,1,1,1,0,0,1,1,0,0,1,0,1,0])

    a_E.SetKey([0,0,0,0,0,0,0,0,0,0,0,0,0,0,1,0])
    print(a_D.Encryption(a_E.Encryption(value)))
