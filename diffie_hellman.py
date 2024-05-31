# Імпортуємо необхідні бібліотеки
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64
import os

# Функція для генерації параметрів для ключа
def generate_parameters():
    # Генеруємо параметри з використанням бібліотеки cryptography
    parameters = dh.generate_parameters(
        generator=2, key_size=512, backend=default_backend()
    )
    return parameters

# Функція для генерації приватного ключа
def generate_private_key(parameters):
    # Використовуємо параметри для генерації приватного ключа
    private_key = parameters.generate_private_key()
    return private_key

# Функція для генерації публічного ключа
def generate_public_key(private_key):
    # Використовуємо приватний ключ для генерації публічного ключа
    public_key = private_key.public_key()
    return public_key

# Функція для генерації спільного ключа
def generate_shared_key(private_key, peer_public_key):
    # Використовуємо приватний ключ та публічний ключ партнера для генерації спільного ключа
    shared_key = private_key.exchange(peer_public_key)
    return shared_key

# Функція для похідного ключа
def derive_key(shared_key, salt=None, length=32):
    # Якщо сіль не вказана, використовуємо стандартну
    if salt is None:
        salt = b"\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B\x0C\x0D\x0E\x0F"
    # Використовуємо PBKDF2 для генерації ключа зі спільного ключа та солі
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        iterations=100000,
        backend=default_backend(),
    )
    key = kdf.derive(shared_key)
    return key, salt

# Функція для шифрування повідомлення
def encrypt_message(key, plaintext):
    # Використовуємо AESGCM для шифрування повідомлення
    aesgcm = AESGCM(key)
    # Генеруємо випадковий nonce
    nonce = os.urandom(12)
    # Шифруємо повідомлення
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    # Повертаємо nonce та зашифроване повідомлення
    return nonce + ciphertext

# Функція для розшифрування повідомлення
def decrypt_message(key, ciphertext):
    # Використовуємо AESGCM для розшифрування повідомлення
    aesgcm = AESGCM(key)
    # Виділяємо nonce з повідомлення
    nonce = ciphertext[:12]
    # Виділяємо зашифроване повідомлення
    encrypted_message = ciphertext[12:]
    # Розшифровуємо повідомлення
    return aesgcm.decrypt(nonce, encrypted_message, None)

# Функція для генерації ключів для учасників
def generate_keys(num_participants):
    # Генеруємо параметри для ключа
    parameters = generate_parameters()
    participants = []
    for _ in range(num_participants):
        try:
            # Генеруємо приватний ключ для кожного учасника
            private_key = generate_private_key(parameters)
        except Exception as e:
            print(f"Помилка при генерації приватного ключа: {e}")
            return
        try:
            # Генеруємо публічний ключ для кожного учасника
            public_key = generate_public_key(private_key)
        except Exception as e:
            print(f"Помилка при генерації публічного ключа: {e}")
            return
        # Додаємо пару ключів до списку учасників
        participants.append((private_key, public_key))
    return participants

# Функція для похідних ключів
def derive_keys(shared_keys):
    symmetric_keys = []
    salts = []
    for shared_key in shared_keys:
        try:
            # Генеруємо похідний ключ для кожного спільного ключа
            symmetric_key, salt = derive_key(shared_key, salt=os.urandom(16))
        except Exception as e:
            print(f"Помилка при виводі ключа: {e}")
            return
        # Додаємо похідний ключ та сіль до відповідних списків
        symmetric_keys.append(symmetric_key)
        salts.append(salt)
    return symmetric_keys, salts

# Функція для перевірки ключів
def verify_keys(num_participants, symmetric_keys_others_to_first, encrypted_keys):
    for i in range(1, num_participants):
        try:
            # Розшифровуємо ключ для кожного учасника
            decrypted_K = decrypt_message(symmetric_keys_others_to_first[i - 1], encrypted_keys[i - 1])
            # Перевіряємо, чи співпадає розшифрований ключ із спільним ключем
            assert decrypted_K == K
        except AssertionError:
            print(f"Помилка при перевірці ключа для учасника {i}")
            return False
    return True

# Головна частина програми
if __name__ == "__main__":
    # Визначаємо кількість учасників
    num_participants = 5
    # Генеруємо ключі для учасників
    participants = generate_keys(num_participants)
    # Генеруємо спільні ключі для першого учасника та всіх інших
    shared_keys = [generate_shared_key(participants[0][0], participants[i][1]) for i in range(1, num_participants)]
    # Генеруємо спільні ключі для інших учасників та першого
    shared_keys_others_to_first = [generate_shared_key(participants[i][0], participants[0][1]) for i in range(1, num_participants)]
    # Генеруємо похідні ключі для спільних ключів
    symmetric_keys, salts = derive_keys(shared_keys)
    # Генеруємо похідні ключі для спільних ключів інших учасників
    symmetric_keys_others_to_first, _ = derive_keys(shared_keys_others_to_first)
    # Генеруємо випадковий ключ K
    K = os.urandom(32)
    # Шифруємо ключ K за допомогою похідних ключів
    encrypted_keys = [encrypt_message(symmetric_key, K) for symmetric_key in symmetric_keys]
    # Перевіряємо, чи всі учасники можуть успішно розшифрувати ключ K
    if verify_keys(num_participants, symmetric_keys_others_to_first, encrypted_keys):
        print("Всі учасники успішно вивели спільний ключ K.")
    else:
        print("Помилка при перевірці ключа.")