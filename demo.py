"""
Демонстрационный скрипт для CryptoVault
Простой пример использования всех основных функций
"""

from cryptovault.cryptovault import CryptoVault
import os

def main():
    print("=" * 60)
    print("CryptoVault - Демонстрация возможностей")
    print("=" * 60)
    print()
    
    # Инициализация системы
    print("1. Инициализация CryptoVault...")
    vault = CryptoVault()
    print("   [OK] Система инициализирована")
    print()
    
    # Регистрация пользователя
    print("2. Регистрация пользователя 'alice'...")
    success, msg = vault.register_user("alice", "SecurePass!@#QWE")
    if success:
        print(f"   [OK] {msg}")
    else:
        print(f"   [ERROR] {msg}")
    print()
    
    # Вход в систему
    print("3. Вход в систему...")
    success, token, msg = vault.login("alice", "SecurePass!@#QWE", ip_address="192.168.1.100")
    if success:
        print(f"   [OK] {msg}")
        print(f"   Токен сессии: {token[:30]}...")
    else:
        print(f"   [ERROR] {msg}")
    print()
    
    # Проверка сессии
    print("4. Проверка сессии...")
    is_valid, username = vault.verify_session(token)
    if is_valid:
        print(f"   [OK] Сессия действительна для пользователя: {username}")
    else:
        print("   [ERROR] Сессия недействительна")
    print()
    
    # Демонстрация криптографии (from scratch)
    print("5. Демонстрация шифра Цезаря (from scratch)...")
    from cryptovault.core.caesar import CaesarCipher, FrequencyAnalyzer
    
    cipher = CaesarCipher(shift=5)
    plaintext = "HELLO WORLD"
    encrypted = cipher.encrypt(plaintext)
    decrypted = cipher.decrypt(encrypted)
    print(f"   Исходный текст: {plaintext}")
    print(f"   Зашифровано: {encrypted}")
    print(f"   Расшифровано: {decrypted}")
    print()
    
    # Частотный анализ
    print("6. Атака частотным анализом...")
    analyzer = FrequencyAnalyzer()
    results = analyzer.attack(encrypted)
    best_shift, best_text, chi_sq = results[0]
    print(f"   Найденный сдвиг: {best_shift}")
    print(f"   Расшифрованный текст: {best_text}")
    print()
    
    # Демонстрация Vigenère
    print("7. Демонстрация шифра Виженера (from scratch)...")
    from cryptovault.core.vigenere import VigenereCipher
    
    vigenere = VigenereCipher(key="KEY")
    plaintext2 = "HELLO"
    encrypted2 = vigenere.encrypt(plaintext2)
    decrypted2 = vigenere.decrypt(encrypted2)
    print(f"   Исходный текст: {plaintext2}")
    print(f"   Зашифровано: {encrypted2}")
    print(f"   Расшифровано: {decrypted2}")
    print()
    
    # Демонстрация SHA-256 (from scratch)
    print("8. Демонстрация SHA-256 (from scratch)...")
    from cryptovault.core.sha256_simplified import SHA256Simplified
    
    data = b"Hello, CryptoVault!"
    hash1 = SHA256Simplified.hash_hex(data)
    hash2 = SHA256Simplified.hash_hex(data)
    print(f"   Данные: {data.decode()}")
    print(f"   Hash: {hash1}")
    print(f"   Hash (повторно): {hash2}")
    print(f"   Хеши совпадают: {hash1 == hash2}")
    print()
    
    # Демонстрация Merkle Tree
    print("9. Демонстрация Merkle Tree (from scratch)...")
    from cryptovault.core.merkle_tree import MerkleTree
    
    leaves = [b"tx1", b"tx2", b"tx3", b"tx4"]
    tree = MerkleTree(leaves)
    root = tree.get_root_hex()
    print(f"   Количество листьев: {len(leaves)}")
    print(f"   Merkle Root: {root}")
    
    # Генерация доказательства
    proof = tree.generate_proof(0)
    print(f"   Доказательство для листа 0: {len(proof)} элементов")
    print()
    
    # Шифрование файла
    print("10. Шифрование файла...")
    test_file = "test_demo.txt"
    encrypted_file = "test_demo.encrypted"
    decrypted_file = "test_demo_decrypted.txt"
    
    try:
        # Создать тестовый файл
        with open(test_file, "w", encoding="utf-8") as f:
            f.write("Это секретное сообщение для демонстрации шифрования файлов!")
        
        print(f"   Создан тестовый файл: {test_file}")
        
        # Зашифровать
        metadata = vault.encrypt_file("alice", test_file, encrypted_file, "filepassword123")
        print(f"   [OK] Файл зашифрован: {encrypted_file}")
        print(f"   Hash файла: {metadata['file_hash'][:20]}...")
        
        # Расшифровать
        result = vault.decrypt_file("alice", encrypted_file, decrypted_file, "filepassword123")
        print(f"   [OK] Файл расшифрован: {decrypted_file}")
        print(f"   Целостность проверена: {result['hash_verified']}")
        print(f"   HMAC проверен: {result['hmac_verified']}")
        
        # Проверить содержимое
        with open(decrypted_file, "r", encoding="utf-8") as f:
            content = f.read()
            print(f"   Содержимое: {content[:50]}...")
        
        # Удалить временные файлы
        if os.path.exists(encrypted_file):
            os.remove(encrypted_file)
        if os.path.exists(decrypted_file):
            os.remove(decrypted_file)
        if os.path.exists(test_file):
            os.remove(test_file)
        
    except Exception as e:
        print(f"   [ERROR] {e}")
    print()
    
    # Информация о блокчейне
    print("11. Информация о блокчейне...")
    info = vault.get_blockchain_info()
    print(f"   Длина цепочки: {info['length']} блоков")
    print(f"   Всего транзакций: {info['total_transactions']}")
    print(f"   Ожидающих транзакций: {info['pending_transactions']}")
    print(f"   Сложность: {info['difficulty']}")
    print(f"   Цепочка валидна: {info['is_valid']}")
    print()
    
    # Проверка целостности блокчейна
    print("12. Проверка целостности блокчейна...")
    is_valid, error = vault.validate_blockchain()
    if is_valid:
        print("   [OK] Блокчейн валиден")
    else:
        print(f"   [ERROR] {error}")
    print()
    
    # Аудит логи
    print("13. Просмотр аудит логов...")
    logs = vault.get_recent_audit_logs(limit=5)
    print(f"   Найдено записей: {len(logs)}")
    for i, log in enumerate(logs[:3], 1):
        print(f"   {i}. {log['event_type']}: {'[OK]' if log['success'] else '[FAIL]'}")
    print()
    
    print("=" * 60)
    print("Демонстрация завершена!")
    print("=" * 60)
    print()
    print("Для более подробной информации см. user_guide.md")

if __name__ == "__main__":
    main()

