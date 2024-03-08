def lcg(seed):
    seed = (3877 * seed + 29573) % 139968
    return seed


def encrypt(text):
    encrypted_text = ""
    key_gen = lcg(11)
    for char in text:
        key_value = lcg(key_gen)
        encrypted_text += chr(ord(char) ^ key_value)

    return encrypted_text


def decrypt(encrypted_text):
    decrypted_text = ""
    key_gen = lcg(11)

    for char in encrypted_text:
        key_value = lcg(key_gen)
        decrypted_text += chr(ord(char) ^ key_value)

    return decrypted_text


choice = input("Для зашифрования введите 1, для расшифрования введите 2. \nВаш выбор - ")

if choice=='1':
    text = input('Введите строку для шифрования: ')
    encrypted_text = encrypt(text)
    print(f"Зашифрованный текст: {encrypted_text}")
elif choice=='2':
    text = input('Введите строку для расшифрования: ')
    decrypted_text = decrypt(text)
    print(f"Расшифрованный текст: {decrypted_text}")
else:
    print("Вы ввели некорректное значения для выбора шифрования/расшифрования")