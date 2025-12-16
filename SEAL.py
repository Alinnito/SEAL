import struct
import os

# Создание таблиц шифрования из ключа
def sha1_G(a, i):
    '''
    a: 20-байтный ключ (160 бит)
    i: 32-битное целое число
    Возвращает 160-битное значение H по 5 32
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

    # 5 32-битных слов
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
    n: 32-битовое число (nonce)
    l: число пройденных итераций из SEAL
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
    n: 32-битовое число (nonce)
    L: требуемая длина выходной последовательности (в байтах)
    R_table: Таблица R
    T_table: Таблица T
    S_table: Таблица S
    Генерирует псевдослучайную последовательность
    '''
    # Изменяемая последовательность байт
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
            P = (P + C) & 0x7FC
            D = D + T_table[P // 4]
            C = C >> 9
            D = D ^ C

            # 4
            Q = (Q + D) & 0x7FC
            A = A ^ T_table[Q // 4]
            D = D >> 9
            A = A + D

            # 5
            P = (P + A) & 0x7FC
            B = B ^ T_table[P // 4]
            A = A >> 9

            # 6
            Q = (Q + B) & 0x7FC
            C = C + T_table[Q // 4]
            B = B >> 9

            # 7
            P = (P + C) & 0x7FC
            D = D ^ T_table[P // 4]
            C = C >> 9

            # 8
            Q = (Q + D) & 0x7FC
            A = A + T_table[Q // 4]
            D = D >> 9

            # Формируем 4 слова, меняем в байты
            bytesLst += (B + S_table[4 * i - 4]).to_bytes(4)
            bytesLst += (C ^ S_table[4 * i - 3]).to_bytes(4)
            bytesLst += (D + S_table[4 * i - 2]).to_bytes(4)
            bytesLst += (A ^ S_table[4 * i - 1]).to_bytes(4)

            # Проверка длины
            if len(bytesLst) >= L:
                return bytesLst[:L]

            if i % 2 != 0:
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

# Исходный текст
text = ('TEST test ТЕСТ тест 1234567890!"№;%:?*()')
text = text.encode('utf8')

# Длина текста
L = len(text)

# Одноразовое число
n = 1

# генерация случайного 20-байтного ключа
key = os.urandom(20)

# Генерируем таблицы T, S, R
T, S, R = build_tables(key)

# Генерируем псевдослучайную последовательность
rmd_sequence = SEAL(n, L, R, T, S)

# Шифруем текст
cithertext = bytes([t ^ s for t, s in zip(text, rmd_sequence)])
print(cithertext)

# Расшифровываем текст
decryptedtext = bytes([t ^ s for t, s in zip(cithertext, rmd_sequence)])
print(decryptedtext.decode('utf8'))
