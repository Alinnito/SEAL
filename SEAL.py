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

    H[0] = (H[0] + A)
    H[1] = (H[1] + B)
    H[2] = (H[2] + C)
    H[3] = (H[3] + D)
    H[4] = (H[4] + E)

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
