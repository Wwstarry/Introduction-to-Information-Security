class S_DES_ASCII():
    P10 = [3, 5, 2, 7, 4, 10, 1, 9, 8, 6]
    P8 = [6, 3, 7, 4, 8, 5, 10, 9]
    IP = [2, 6, 3, 1, 4, 8, 5, 7]
    IPInverse = [4, 1, 3, 5, 7, 2, 8, 6]
    ExtendP = [4, 1, 2, 3, 2, 3, 4, 1]
    SP = [2, 4, 3, 1]
    SB1 = [[1, 0, 3, 2],
           [3, 2, 1, 0],
           [0, 2, 1, 3],
           [3, 1, 0, 2]]
    SB2 = [[0, 1, 2, 3],
           [2, 3, 1, 0],
           [3, 0, 1, 2],
           [2, 1, 0, 3]]
    K = []
    K1 = []
    K2 = []

    def __init__(self) -> None:
        pass

    def GetKey(self):
        return ''.join(map(str, self.K))

    def Encryption(self, InputBits):
        Step0 = self.PBox(InputBits=InputBits, PermutationTable=self.IP, OutPutLength=8)
        Step1 = self.FeistelFunction(Step0, self.K1, self.K2)
        return self.PBox(InputBits=Step1, PermutationTable=self.IPInverse, OutPutLength=8)

    def Decryption(self, InputBits):
        Step0 = self.PBox(InputBits=InputBits, PermutationTable=self.IP, OutPutLength=8)
        Step1 = self.FeistelFunction(Step0, self.K2, self.K1)
        return self.PBox(InputBits=Step1, PermutationTable=self.IPInverse, OutPutLength=8)

    def XOR(self, list1, list2):
        return [bit1 ^ bit2 for bit1, bit2 in zip(list1, list2)]

    def FeistelFunction(self, InputBits: list, K1, K2):
        RightPart = InputBits[-4:]
        LeftPart = InputBits[:4]
        AfterEP = self.PBox(InputBits=RightPart, PermutationTable=self.ExtendP, OutPutLength=8)
        AfterXOR = self.XOR(AfterEP, K1)
        AfterS1 = self.SBox(InputBits=AfterXOR[:4], SubstitutionBox=self.SB1)
        AfterS2 = self.SBox(InputBits=AfterXOR[-4:], SubstitutionBox=self.SB2)
        OutPut0 = self.PBox(InputBits=AfterS1 + AfterS2, PermutationTable=self.SP, OutPutLength=4)

        Temp = LeftPart
        LeftPart = RightPart
        RightPart = self.XOR(Temp, OutPut0)

        AfterEP = self.PBox(InputBits=RightPart, PermutationTable=self.ExtendP, OutPutLength=8)
        AfterXOR = self.XOR(AfterEP, K2)
        AfterS1 = self.SBox(InputBits=AfterXOR[:4], SubstitutionBox=self.SB1)
        AfterS2 = self.SBox(InputBits=AfterXOR[-4:], SubstitutionBox=self.SB2)
        OutPut0 = self.PBox(InputBits=AfterS1 + AfterS2, PermutationTable=self.SP, OutPutLength=4)
        LeftResult = self.XOR(LeftPart, OutPut0)
        RightResult = RightPart

        return LeftResult + RightResult

    def SetKey(self, InputBits: list):
        """列表形式给定10bit密钥,并且生成对应的子密钥"""
        self.K = InputBits
        AfterP10 = self.PBox(InputBits=self.K, PermutationTable=self.P10, OutPutLength=10)
        LeftPartV1 = [AfterP10[:5][(i + 1) % 5] for i in range(5)]
        RightPartV1 = [AfterP10[-5:][(i + 1) % 5] for i in range(5)]
        self.K1 = self.PBox(InputBits=LeftPartV1 + RightPartV1, PermutationTable=self.P8, OutPutLength=8)
        LeftPartV2 = [AfterP10[:5][(i + 2) % 5] for i in range(5)]
        RightPartV2 = [AfterP10[-5:][(i + 2) % 5] for i in range(5)]
        self.K2 = self.PBox(InputBits=LeftPartV2 + RightPartV2, PermutationTable=self.P8, OutPutLength=8)

    def BinaryList2Decimal(self, InputBits: list):
        BinaryString = ''.join(str(bit) for bit in InputBits)
        Decimal = int(BinaryString, 2)
        return Decimal

    def Decimal2BinaryList(self, Number: int):
        BinaryString = bin(Number)
        BinaryList = [int(x) for x in BinaryString[2:]]
        while len(BinaryList) < 2:
            BinaryList.insert(0, 0)
        return BinaryList

    def PBox(self, InputBits, PermutationTable, OutPutLength):
        """ 
        置换盒，需要用列表的形式传入任意bit数据，并且给定置换表,并且要求填入输出长度
        """
        output_bits = [InputBits[i - 1] for i in PermutationTable]
        return output_bits[:OutPutLength]

    def SBox(self, InputBits, SubstitutionBox):
        """混淆盒，需要用列表的形式传入4bit数据，并且给定二维数组混淆表"""
        RowBinary = [InputBits[0], InputBits[3]]
        ColumnBinary = [InputBits[1], InputBits[2]]
        Row = self.BinaryList2Decimal(RowBinary)
        Column = self.BinaryList2Decimal(ColumnBinary)
        return self.Decimal2BinaryList(SubstitutionBox[Row][Column])

    def binary_to_garbage(self, binary_list: list) -> str:
        """将二进制列表转换为乱码字符"""
        garbage_chars = []
        for i in range(0, len(binary_list), 8):
            byte = binary_list[i:i + 8]
            byte_value = int(''.join(map(str, byte)), 2)
            garbage_chars.append(chr(byte_value))
        return ''.join(garbage_chars)

    def garbage_to_binary(self, garbage_str: str) -> list:
        """将乱码字符转换为二进制列表"""
        binary_list = []
        for char in garbage_str:
            binary_char = format(ord(char), '08b')
            binary_list.extend([int(bit) for bit in binary_char])
        return binary_list
    
    def Encryption_ASCII(self, plaintext: str, key) -> str:
        """将ASCII明文加密并返回乱码"""
        binary_plaintext = ''.join(format(ord(c), '08b') for c in plaintext)
        encrypted_binary = ''
        for i in range(0, len(binary_plaintext), 8):
            block = list(map(int, binary_plaintext[i:i + 8]))
            encrypted_block = self.Encryption(block)
            encrypted_binary += ''.join(str(b) for b in encrypted_block)
        return self.binary_to_garbage(list(map(int, encrypted_binary)))

    def Decryption_ASCII(self, ciphertext: str, key) -> str:
        """将加密的乱码密文解密并恢复为明文"""
        binary_ciphertext = self.garbage_to_binary(ciphertext)
        decrypted_binary = ''
        for i in range(0, len(binary_ciphertext), 8):
            block = binary_ciphertext[i:i + 8]
            decrypted_block = self.Decryption(block)
            decrypted_binary += ''.join(str(b) for b in decrypted_block)
        decrypted_chars = []
        for i in range(0, len(decrypted_binary), 8):
            num = int(decrypted_binary[i:i + 8], 2)
            decrypted_chars.append(chr(num))
        return ''.join(decrypted_chars)

if __name__ == "__main__":
    machine = S_DES()
    machine.SetKey([1, 1, 1, 1, 1, 1, 1, 1, 1, 0])

    # 使用bit加密
    P = [1, 0, 0, 1, 1, 0, 1, 0]
    print("明文为：", P)
    C = machine.Encryption(P)
    print("加密结果为：", C)
    PD = machine.Decryption(C)
    print("解密结果为：", PD)

    # 使用ASCII加密，生成乱码
    plaintext = "love"
    print(f"原始明文: {plaintext}")

    # 加密并生成乱码
    encrypted_text = machine.Encryption_ASCII(plaintext, machine.K)
    print(f"加密结果: {encrypted_text}")

    # 解密回明文
    decrypted_text = machine.Decryption_ASCII(encrypted_text, machine.K)
    print(f"解密结果: {decrypted_text}")
