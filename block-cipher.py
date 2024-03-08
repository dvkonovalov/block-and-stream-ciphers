"""
Реализация алгоритма блочного шифрования IDEA
"""
from bitstring import BitArray


def xor(num1, num2):
    """
    Поразрядное сложение по модулю 2 (операция "исключающее ИЛИ")
    :param num1: Первое число
    :param num2: Второе число
    :return: Результат поразрядного сложения
    """
    num1 = int.from_bytes(num1, byteorder='big')
    num2 = int.from_bytes(num2, byteorder='big')
    result = num1 ^ num2
    return result.to_bytes(2, byteorder='big')


def add(num1, num2):
    """
    Сложение беззнаковых целых по модулю 65536=2^{16}
    :param num1: Первое число
    :param num2: Второе число
    :return: Результат сложения
    """
    num1 = int.from_bytes(num1, byteorder='big')
    num2 = int.from_bytes(num2, byteorder='big')
    result = (num1 + num2) % 65536
    return result.to_bytes(2, byteorder='big')


def mul(num1, num2):
    """
    Умножение целых по модулю 65537=2^{16}+1, рассматриваемых как беззнаковые целые,
    за исключением того, что блок из 16 нулей рассматривается как 2^{16}
    :param num1: Первое число
    :param num2: Второе число
    :return: Результат умножения
    """
    num1 = int.from_bytes(num1, byteorder='big')
    num2 = int.from_bytes(num2, byteorder='big')
    if num1 == 0:
        num1 = 65536
    if num2 == 0:
        num2 = 65536
    result = (num1 * num2) % 65537
    if result == 65536:
        result = 0
    return result.to_bytes(2, byteorder='big')


def reverse_element(element):
    """
     Нахождение обратного по умножению элемента по модулю 65537
    :param element: элемент к которому ищем обратный
    :return: обратный элемент
    """
    element = int.from_bytes(element, byteorder='big')
    if element == 0:
        element = 65536
    rev_element = 0
    while (rev_element * element) % 65537 != 1:
        rev_element += 1
    if rev_element == 65536:
        rev_element = 0
    return rev_element.to_bytes(2, byteorder='big')


def opposite_element(element):
    """
    Нахождение противоположного элемента по модулю 65536
    :param element: элемент к которому ищем обратный
    :return:
    """
    element = int.from_bytes(element, byteorder='big')
    op_element = 0
    while (element + op_element) % 65536 != 0:
        op_element += 1
    return op_element.to_bytes(2, byteorder='big')


def cyclic_shift_left(binary_string):
    """
    Циклический сдвиг влево на 25 позиций
    :param binary_string: строка для сдвига
    :return: строка после сдвига
    """
    bit_array = BitArray(binary_string)
    binary_string = bit_array << 25 | bit_array >> (len(bit_array) - 25)
    binary_string = binary_string.bytes
    return binary_string


def generation_keys(primary_key):
    """
    Функция генерации ключей для алгоритма IDEA
    :param primary_key: Начальный ключ
    :return: Массив с 52 подключами длинной 16 бит
    """
    keys = []
    for i in range(7):
        k = 8
        if i == 6:
            k = 4
        for j in range(k):
            keys.append(primary_key[j * 2:j * 2 + 2])
        primary_key = cyclic_shift_left(primary_key)
    return keys


def encrypt(block, keys):
    """
    Функция шифрования блока
    :param block: блок
    :param keys: 52 подключа
    :return: выходной зашифрованный блок
    """
    x1 = block[0:2]
    x2 = block[2:4]
    x3 = block[4:6]
    x4 = block[6:8]

    steps = [b''] * 10

    for i in range(8):
        steps[0] = mul(x1, keys[i * 6])
        steps[1] = add(x2, keys[i * 6 + 1])
        steps[2] = add(x3, keys[i * 6 + 2])
        steps[3] = mul(x4, keys[i * 6 + 3])
        steps[4] = xor(steps[0], steps[2])
        steps[5] = xor(steps[1], steps[3])
        steps[6] = mul(steps[4], keys[i * 6 + 4])
        steps[7] = add(steps[5], steps[6])
        steps[8] = mul(steps[7], keys[i * 6 + 5])
        steps[9] = add(steps[6], steps[8])

        x1 = xor(steps[0], steps[8])
        x2 = xor(steps[2], steps[8])
        x3 = xor(steps[1], steps[9])
        x4 = xor(steps[3], steps[9])
    x2, x3 = x3, x2
    x1 = mul(x1, keys[48])
    x2 = add(x2, keys[49])
    x3 = add(x3, keys[50])
    x4 = mul(x4, keys[51])

    return x1 + x2 + x3 + x4


def encrypt_file(path, key):
    """
    Функция для шифрования файла
    :param path: путь к файлу
    :param key: первичный ключ
    """
    keys = generation_keys(key)
    with open(path, "rb") as file:
        binary_data = file.read()
    pos = 0
    ret_result = b''
    while pos <= len(binary_data)+7:
        if pos == len(binary_data):
            binary_data = b'\x00' * 7 + b'8'
        elif pos > len(binary_data):
            binary_data = binary_data[pos:] + b'\x00' * (8 - pos + len(binary_data) - 1) + bytes(
                str(8 - pos + len(binary_data)), 'utf-8')
            print(binary_data)
        ret_result += encrypt(binary_data[pos:pos + 8], keys)
        pos += 8
    with open("encrypt.txt", "wb") as file:
        file.write(ret_result)
    print("Файл успешно зашифрован и помещен в encrypt.txt")


def decrypt_file(path, key):
    """
    Функция для расшифрования файла
    :param path: путь к зашифрованному файлу
    :param key: первичный ключ
    """
    keys = generation_keys(key)
    decrypt_keys = [reverse_element(keys[48]), opposite_element(keys[49]), opposite_element(keys[50]),
                    reverse_element(keys[51])]

    for i in range(8):
        decrypt_keys.append(keys[47 - i * 6 - 1])
        decrypt_keys.append(keys[47 - i * 6])
        decrypt_keys.append(reverse_element(keys[47 - i * 6 - 5]))
        decrypt_keys.append(opposite_element(keys[47 - i * 6 - 3]))
        decrypt_keys.append(opposite_element(keys[47 - i * 6 - 4]))
        decrypt_keys.append(reverse_element(keys[47 - i * 6 - 2]))
    decrypt_keys[49], decrypt_keys[50] = decrypt_keys[50], decrypt_keys[49]

    with open(path, "rb") as file:
        binary_data = file.read()
    pos = 0
    ret_result = b''
    while pos < len(binary_data):
        ret_result += encrypt(binary_data[pos:pos + 8], keys)
        pos += 8
    last_symbol = ret_result[-1]
    print(ret_result)
    print(last_symbol)
    ret_result = ret_result[:-last_symbol-1]

    with open("decrypt.txt", "wb") as file:
        file.write(ret_result)
    print("Файл успешно расшифрован и помещен в decrypt.txt")



# encrypt_file('text.txt', b'\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08')
# decrypt_file('encrypt.txt', b'\x00\x01\x00\x02\x00\x03\x00\x04\x00\x05\x00\x06\x00\x07\x00\x08')