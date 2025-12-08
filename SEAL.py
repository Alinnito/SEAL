import struct

# Создание таблиц шифрования из ключа
def sha1_G(a, i):
    '''
    a: 20-байтный ключ (160 бит)
    i: 32-битное целое число
    Возвращаем 160-битное значение Ga(i)
    '''

    # Разбиваем 160-битовую строку на 5 32-битных слов
    H = list(struct.unpack('>5I', a))

    # SHA-1
    W = [0]*80
    W[0] = i

    for t in range(16, 80):
        W[t] = (W[t-3] ^ W[t-8] ^ W[t-14] ^ W[t-16] << 1)

    A, B, C, D, E = H[0], H[1], H[2], H[3], H[4]

    for t in range(80):
        if 0 <= t <= 19:
            K = 0x5a827999
            f = (B & C) | (not B & D)
        elif 20 <= t <= 39:
            K = 0x6ed9eba1
            f = B ^ C ^ D
        elif 40 <= t <= 59:
            K = 0x8f1bbcdc
            f = (B & C) | (B & D) | (C & D)
        else:
            K = 0xca62c1d6
            f = B ^ C ^ D

        TEMP = ((A << 5) + f + E + W[t] + K)
        E = D
        D = C
        C = B << 30
        B = A
        A = TEMP

    H[0] = (H[0] + A) & 0xffffffff
    H[1] = (H[1] + B) & 0xffffffff
    H[2] = (H[2] + C) & 0xffffffff
    H[3] = (H[3] + D) & 0xffffffff
    H[4] = (H[4] + E) & 0xffffffff

    return H

def word_H(a, i):
    '''
    a: 20-байтный ключ
    i: число
    Возвращает одно 32-битное слово H
    '''
    j = i // 5
    index = i % 5
    H = sha1_G(a, j)
    return H[index]

# Построение таблиц
def build_tables(a):
    '''
    a: 20-байтный ключ
    Возвращает таблицы T, S, R
    '''
    T = [0] * 512
    S = [0] * 256
    R = [0] * 256

    for i in range(512):
        T[i] = word_H(a, i)

    for j in range(256):
        S[j] = word_H(a, 0x1000 + j)

    for k in range(256):
        R[k] = word_H(a, 0x2000 + k)

    return T, S, R

# Инициализация служебных регистров

def registers_init(n, l, R_table, T_table):
    '''
    n:
    l:
    R_table: таблица R
    T_table: таблица T
    Возвращает 4 32-битовых служебных регистра (A, B, C, D) и 4 32-битовых слова (n1, n2, n3, n4)
    '''

    # Инициализация регистров
    A = (n ^ R_table[4 * l])
    B = (n ^ T_table[4 * l + 1])
    C = (n ^ T_table[4 * l + 2])
    D = (n ^ T_table[4 * l + 3])

    # Цикл на 2 повтора
    for j in range(2):
        P = A & 0x7FC
        B = B + T_table[P // 4]
        A = A >> 9

        P = B & 0x7FC
        C = C + T_table[P // 4]
        B = B >> 9

        P = C & 0x7FC
        D = D + T_table[P // 4]
        C = C >> 9

        P = D & 0x7FC
        A = A + T_table[P // 4]
        D = D >> 9

    # Присваиваем значения
    n1, n2, n3, n4 = D, B, A, C

    # Аналогичный код из цикла
    P = A & 0x7FC
    B = B + T_table[P // 4]
    A = A >> 9

    P = B & 0x7FC
    C = C + T_table[P // 4]
    B = B >> 9

    P = C & 0x7FC
    D = D + T_table[P // 4]
    C = C >> 9

    P = D & 0x7FC
    A = A + T_table[P // 4]
    D = D >> 9

    return A, B, C, D, n1, n2, n3, n4

# Псевдослучайная функция
def SEAL(n, L, R_table, T_table, S_table):
    '''
    n: 32-битный индекс
    L: требуемая длина выходной последовательности (в байтах)
    R_table: Таблица R
    T_table: Таблица T
    S_table: Таблица S
    Генерирует псевдослучайную последовательность
    '''
    # Изменяемый массив байт
    bytesLst = bytearray()

    l = 0 # Количество пройденных итераций

    while True:
        A, B, C, D, n1, n2, n3, n4 = registers_init(n, l, R_table, T_table)

        l += 1

        for i in range(1, 65):

            # 1
            P = A & 0x7FC
            B = B + T_table[P // 4]
            A = A >> 9
            B = B ^ A

            # 2
            Q = B & 0x7FC
            C = C ^ T_table[Q // 4]
            B = B >> 9
            C = C + B

            # 3
            P = P + C
            D = D + T_table[P // 4]
            C = C >> 9
            D = D ^ C

            # 4
            Q = (Q + D) & 0x7FC
            A = A ^ T_table[Q // 4]
            D = D >> 9
            A = A + D

            # 5
            P = P + A
            B = B ^ T_table[P // 4]
            A = A >> 9

            # 6
            Q = (Q + B) & 0x7FC
            C = C + T_table[Q // 4]
            B = B >> 9

            # 7
            P = P + C
            D = D ^ T_table[P // 4]
            C = C >> 9

            # 8
            Q = (Q + D) & 0x7FC
            A = A + T_table[Q // 4]
            D = D >> 9

            # Формируем 4 слова, меняем в байты
            bytesLst += (B + S_table[4 * i - 4]).to_bytes(4, byteorder='big')
            bytesLst += (C ^ S_table[4 * i - 3]).to_bytes(4, byteorder='big')
            bytesLst += (D + S_table[4 * i - 2]).to_bytes(4, byteorder='big')
            bytesLst += (A ^ S_table[4 * i - 1]).to_bytes(4, byteorder='big')

            # Проверка длины
            if len(bytesLst) >= L:
                return bytes(bytesLst[:L])

            if i & 1:
                # Нечетное i
                A = A + n1
                B = B + n2
                C = C ^ n1
                D = D ^ n2
            else:
                # Четное i
                A = A + n3
                B = B + n4
                C = C ^ n3
                D = D ^ n4

key = b'\x01\x23\x45\x67\x89\xab\xcd\xef\xfe\xdc\xba\x98\x76\x54\x32\x10\x11\x22\x33\x44'

T, S, R = build_tables(key)

print(len(T))
print(len(S))
print(len(R))

print(T[0:9])
print(S[0:9])
print(R[0:9])