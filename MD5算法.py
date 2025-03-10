import struct
import math


def left_rotate(x, n):
    return (x << n) | (x >> (32 - n)) & 0xFFFFFFFF


class MD5:
    def __init__(self):
        self.A = 0x67452301
        self.B = 0xEFCDAB89
        self.C = 0x98BADCFE
        self.D = 0x10325476
        # 使用sin函数生成的T
        self.T = [int(abs(2 ** 32 * abs(math.sin(i + 1)))) for i in range(64)]
        self.s = [
            7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
            5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
            4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
            6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21
        ]

    def update(self, msg):
        # 填充
        msg = self.padding(msg)
        # 分块
        blocks = self.split_blocks(msg)
        # 对每个block进行循环
        for block in blocks:
            # 进入主循环
            self.process_block(block)

    def padding(self, msg):
        # 计算位(bit)的数量；
        # orig_len保存原始长度
        orig_len = len(msg) * 8
        # 在消息末尾填充一个1个字节的\x80
        # 增加的位为10000000
        msg += b'\x80'
        # 取余后做零字节填充，直到满足56个字节
        while (len(msg) * 8) % 512 != 448:
            # 增加一个全零字节，位为00000000
            msg += b'\x00'
        # 最后附加一个原始长度64位的2进制数来凑成64个字节
        # <表示小端序，Q表示64位；
        # 该代码的意思就是将明文始终变成8个字节的16进制小端序编码
        # 并添加到msg的后面凑成64个字节512位
        msg += struct.pack('<Q', orig_len)
        return msg

    def split_blocks(self, msg):
        # 将64个字节512位倍数的二进制编码分成n个每个64位的block
        # 最后返回一个二维列表
        return [msg[i:i + 64] for i in range(0, len(msg), 64)]

    def process_block(self, block):
        A, B, C, D = self.A, self.B, self.C, self.D
        # 将512位的block分成16个32位的words，并进行64次迭代
        words = struct.unpack('<16I', block)
        # 64次逻辑迭代
        for i in range(64):
            # 前16次
            if i < 16:
                F = (B & C) | (~B & D)
                g = i
            # 16-32次
            elif i < 32:
                F = (D & B) | (~D & C)
                g = (5 * i + 1) % 16
            # 32-48次
            elif i < 48:
                F = B ^ C ^ D
                g = (3 * i + 5) % 16
            # 48-64次
            else:
                F = C ^ (B | ~D)
                g = (7 * i) % 16
            # 更新F的值，A的值会一直被轮换，执行非线性的混淆运算
            F = (F + A + self.T[i] + words[g]) & 0xFFFFFFFF
            # 更新寄存器使用循环左移s表中的位数，并通过如下结构更替寄存器
            # 变量轮换
            A, D, C, B = D, C, B, (B + left_rotate(F, self.s[i])) & 0xFFFFFFFF
        #  更新此次循环最终寄存器的值，并确保为32位
        self.A = (self.A + A) & 0xFFFFFFFF
        self.B = (self.B + B) & 0xFFFFFFFF
        self.C = (self.C + C) & 0xFFFFFFFF
        self.D = (self.D + D) & 0xFFFFFFFF

    def digest(self):
        # <表示小端序，4表示4个，I表示32位的数
        # 将4个32位的寄存器打包拼接成2进制的总共16个字节的哈希值
        return struct.pack('<4I', self.A, self.B, self.C, self.D)

    def hexdigest(self):
        # 将二进制的哈希值转化成16进制
        return self.digest().hex()


if __name__ == "__main__":
    md5 = MD5()
    # 使用二进制模式打开文件
    with open("数据采集客观题1.docx", "rb") as file:
        data = file.read()
    md5.update(data)
    print(md5.hexdigest()) # 输出：e5044f503068d85bd38e2b22503e9e1d
