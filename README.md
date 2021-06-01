# Slack бот для поиска материалов в базе WikiWorks

Для работы бота необходимо наличие python3

## Настройка бота

```shell
python3 -m venv venv
source venv/bin/activate
pip3 install -r requirements/dev.txt
```

Далее необходимо переименовать `example.env` в `.env` указав полученные в интерфейсе Slak коды доступа

Константу `CRYPTO_KEY` вы можете получить следующим образом:
```python
from cryptography.fernet import Fernet
key = Fernet.generate_key()
```
