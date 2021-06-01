import json
import re

import cryptography
import requests
from django.conf import settings

import ssl
import slack
from django.http import JsonResponse, HttpResponse

from actions.models import BotUser


def make_login_submission(json_dict):
    """
    Проверяем введенные логин, пароль и домен
    """
    credentials = json_dict['view']['state']['values'].values()

    login, password, domain = '', '', ''
    short_pattern = r'^[a-zA-Z0-9\-]*'
    long_pattern = r'^[a-zA-Z0-9\-]*\.wikiworks\.io'

    for info in credentials:
        if info.get('login'):
            login = info['login']['value']
        if info.get('password'):
            password = info['password']['value']
        if info.get('domain'):
            domain = info['domain']['value']

    if re.fullmatch(short_pattern, domain):
        url = f'{domain}.wikiworks.io'
    elif re.fullmatch(long_pattern, domain):
        url = domain
    else:
        return JsonResponse(MessageTemplates.show_error('domain', 'Вы неправильно указали портал'), status=200)

    ww = WikiworksConnector(url)
    status_code, _ = ww.check_credentials(login=login, password=password)

    if status_code == 400:
        return JsonResponse(MessageTemplates.show_error('login', 'Логин или пароль указаны неверно'), status=200)
    if status_code == 404:
        return JsonResponse(MessageTemplates.show_error('domain', 'Данный портал еще не зарегистрирован'), status=200)
    elif status_code == 200:
        create_bot_user(json_dict['user']['id'], login, password, url)
        return HttpResponse(status=200)


def create_bot_user(slack_user_id, login, password, domain):
    user = BotUser.objects.create(slack_user_id=slack_user_id)
    user.wikiworks_login = BotUser.encrypt(login)
    user.wikiworks_password = BotUser.encrypt(password)
    user.wikiworks_domain = BotUser.encrypt(domain)
    user.save()


def make_login_button(json_dict, trigger_id):
    slack_instance = SlackConnector()

    try:
        user = json_dict['user']['id']
    except AttributeError:
        return HttpResponse(status=400)

    authorized = False
    if BotUser.objects.filter(slack_user_id=user).exists():
        authorized = True

    slack_instance.show_modal(trigger_id=trigger_id, authorized=authorized)

    return HttpResponse(status=200)


class MessageTemplates:
    """
    Класс шаблонов сообщений
    """

    LOGIN_OR_PASS_WRONG = {
        'response_action': 'errors',
        'errors': {
            'login': 'Логин или пароль указаны неверно',
        },
    }

    @staticmethod
    def show_error(field, text):
        return {
            'response_action': 'errors',
            'errors': {
                field: text,
            },
        }

    BUTTON_LOGIN_PROMPT = 'button_login_prompt'
    AUTHORIZATION_MODAL_ID = 'authorization_modal_id'
    LOGIN_PROMPT = [
        {
            'type': 'section',
            'block_id': 'section-identifier',
            'text': {
                'type': 'mrkdwn',
                'text': 'Готов к поиску, но сначала пройдите авторизацию',
            },
            'accessory': {
                'type': 'button',
                'text': {
                    'type': 'plain_text',
                    'text': 'Авторизоваться',
                },
                'action_id': BUTTON_LOGIN_PROMPT,
            },
        },
    ]
    AUTHORIZED = {
        'title': {
            'type': 'plain_text',
            'text': 'Вы уже авторизированны',
        },
        'submit': {
            'type': 'plain_text',
            'text': 'Ok',
        },
        'blocks': [
            {
                'type': 'context',
                'elements': [
                    {
                        'type': 'plain_text',
                        'text': 'Дополнительная авторизация не требуется',
                    },
                ],
            },
        ],
        'type': 'modal',
    }
    AUTHORIZATION = {
        'callback_id': AUTHORIZATION_MODAL_ID,
        'title': {
            'type': 'plain_text',
            'text': 'Авторизация пользователя',
        },
        'submit': {
            'type': 'plain_text',
            'text': 'Авторизоваться',
        },
        'blocks': [
            {
                'type': 'input',
                'block_id': 'login',
                'element': {
                    'type': 'plain_text_input',
                    'action_id': 'login',
                    'placeholder': {
                        'type': 'plain_text',
                        'text': 'Введите логин',
                    },
                },
                'label': {
                    'type': 'plain_text',
                    'text': 'Логин',
                },
            },
            {
                'type': 'input',
                'block_id': 'password',
                'element': {
                    'type': 'plain_text_input',
                    'action_id': 'password',
                    'placeholder': {
                        'type': 'plain_text',
                        'text': 'Введите пароль',
                    },
                },
                'label': {
                    'type': 'plain_text',
                    'text': 'Пароль',
                },
            },
            {
                'type': 'input',
                'block_id': 'domain',
                'element': {
                    'type': 'plain_text_input',
                    'action_id': 'domain',
                    'placeholder': {
                        'type': 'plain_text',
                        'text': 'Введите название портала (например demo или demo.wikiworks.io)',
                    },
                },
                'label': {
                    'type': 'plain_text',
                    'text': 'Портал',
                },
            },
        ],
        'type': 'modal',
    }

    @staticmethod
    def result_text(result, link=None, highlight=None):
        if link:
            text = f'<http://{link}|{result}>'
        else:
            text = result
        if highlight:
            text += f'\n({highlight})'
        block = [
            {
                'type': 'section',
                'text': {
                    'type': 'mrkdwn',
                    'text': text,
                },
            },
        ]
        return block


class SlackConnector:
    """
    Класс для коммуникации со SLack API
    """

    def __init__(self):
        ssl_context = ssl.create_default_context()
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
        self.client = slack.WebClient(token=settings.BOT_USER_ACCESS_TOKEN, ssl=ssl_context)

    def del_message(self, channel, ts):
        """
        Удаляем сообщение
        """
        self.client.chat_delete(channel=channel, ts=ts)

    def show_modal(self, trigger_id, authorized=False):
        """
        Отображаем модальное окно
        """
        if authorized:
            self.client.views_open(trigger_id=trigger_id, view=MessageTemplates.AUTHORIZED)
        else:
            self.client.views_open(trigger_id=trigger_id, view=MessageTemplates.AUTHORIZATION)

    def send_message(self, channel, blocks):
        """
        Отправляем сообщение в чат
        """
        send_instance = self.client.chat_postMessage(channel=channel, blocks=blocks)

        if send_instance.get('ok', False) is True:
            return {
                'channel': send_instance.get('channel'),
                'ts': send_instance.get('ts'),
            }


class WikiworksConnector:
    """
    Класс для коммуникации с Wikiworks API
    """

    def __init__(self, domain):
        self.domain = domain

    def check_credentials(self, login: str, password: str) -> (int, str):
        """
        Проверяем существование пользователя и получаем токен существующего пользователя
        """
        data = {
            'email': login,
            'password': password,
        }
        url = 'https://' + self.domain + '/api/v1/token/'
        response = requests.post(url, json=data)
        status_code = response.status_code

        if status_code == 404:
            return status_code, None

        return status_code, json.loads(response.content.decode('utf-8'), encoding='utf-8')

    def get_search_results(self, query, token, results=None, url=None):
        """
        Получаем результаты поиска
        """
        if not url:
            url = 'https://' + self.domain + '/api/v1/knowledge-base/'

        response = requests.get(url,
                                params={'search': query},
                                headers={'Authorization': f'Token {token}'})

        if response.status_code != 200:
            return {'error': 'Ошибка получения данных'}

        response_json = json.loads(response.content.decode('utf-8'), encoding='utf-8')

        if len(response_json['results']) == 0:
            return {'results': []}

        next_link = response_json['next']
        results = results or []

        for result in response_json['results']['rubrics']:
            results = self.__parse_results(result['materials'], results)

        results = self.__parse_results(response_json['results']['materials'], results)

        if next_link:
            self.get_search_results(query=query, token=token, results=results, url=next_link)

        return {'results': results}

    def __parse_results(self, data, results):
        for material in data:
            text = self.__make_markdown(material['title'])
            highlight = None
            try:
                highlight = self.__make_markdown(material['highlight'])
            except KeyError:
                pass
            results.append({
                'result': text,
                'link': self.domain + material['link'],
                'highlight': highlight,
            })
        return results

    @staticmethod
    def __make_markdown(text):
        """
        Удаляем все лишние теги из текста
        """
        pattern = r'<span(?:"[^"]*"[\'"]*|\'[^\']*\'[\'"]*|[^\'">])+>|<\/span>'
        text = re.sub(pattern, '*', text)
        text = re.sub(r'<(?:"[^"]*"[\'"]*|\'[^\']*\'[\'"]*|[^\'">])+>', '', text)
        return re.sub(r'&(?:[a-zA-Z]*)+;', '', text)


def show_search_results(response, channel, slack_instance):
    if len(response['results']) == 0:
        result = 'Ничего не найдено'
        slack_instance.send_message(channel=channel, blocks=MessageTemplates.result_text(result))
    else:
        for res in response['results']:
            result = res['result']
            link = res['link']
            highlight = res['highlight']
            slack_instance.send_message(channel=channel,
                                        blocks=MessageTemplates.result_text(result, link, highlight))


def get_token(user: str, ww: WikiworksConnector):
    bot_user = BotUser.objects.get(slack_user_id=user)
    try:
        hash_login = BotUser.decrypt(bot_user.wikiworks_login)
        hash_password = BotUser.decrypt(bot_user.wikiworks_password)
    except cryptography.fernet.InvalidToken:
        return None

    status, token = ww.check_credentials(login=hash_login, password=hash_password)

    if status != 200:
        token = None

    return token
