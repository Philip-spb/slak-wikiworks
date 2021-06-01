from django.conf import settings
from django.db import models
from cryptography.fernet import Fernet


class BotUser(models.Model):
    slack_user_id = models.CharField(max_length=128, verbose_name='ID пользователя slack')
    wikiworks_domain = models.CharField(max_length=128, verbose_name='Портал пользователя wikiworks', blank=True)
    wikiworks_login = models.CharField(max_length=128, verbose_name='Логин пользователя wikiworks', blank=True)
    wikiworks_password = models.CharField(max_length=128, verbose_name='Пароль пользователя wikiworks', blank=True)

    @staticmethod
    def encrypt(string: str) -> str:
        return Fernet(settings.CRYPTO_KEY).encrypt(string.encode('utf-8')).decode('utf-8')

    @staticmethod
    def decrypt(string: str) -> str:
        return Fernet(settings.CRYPTO_KEY).decrypt(string.encode('utf-8')).decode('utf-8')

    def __str__(self):
        return self.slack_user_id


class SentMessages(models.Model):
    """
    ID полученных сообщений от бота храним для того чтобы повторно их не показывать
    """
    client_msg_id = models.CharField(max_length=64, verbose_name='ID отправленного сообщения')

    def __str__(self):
        return self.client_msg_id
