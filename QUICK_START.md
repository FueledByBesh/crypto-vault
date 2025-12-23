# Быстрый старт CryptoVault

## Запуск демонстрации

### Вариант 1: Через командную строку
```bash
py demo.py
```

### Вариант 2: Двойной клик
Запустите файл `run_demo.bat`

### Вариант 3: Интерактивный Python
```python
from cryptovault.cryptovault import CryptoVault

# Создать систему
vault = CryptoVault()

# Зарегистрировать пользователя
vault.register_user("alice", "SecurePass123!")

# Войти
vault.login("alice", "SecurePass123!")

# Использовать функции...
```

## Примеры использования

См. файл `demo.py` для полной демонстрации всех возможностей.

