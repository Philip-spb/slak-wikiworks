from django.views.decorators.csrf import csrf_exempt
from django.conf import settings
import json
from django.http import HttpResponse, JsonResponse

from urllib.parse import unquote_plus

from actions.models import BotUser, SentMessages
from actions.services import (MessageTemplates, SlackConnector, WikiworksConnector, make_login_submission,
                              make_login_button, get_token, show_search_results)


@csrf_exempt
def interactivity_hook(request):
    """
    Обработка событий в модельных окнах
    """
    res = unquote_plus(request.body.decode('utf-8')).split('payload=')[1]
    json_dict = json.loads(res, encoding='utf-8')
    trigger_id = json_dict['trigger_id']

    is_login_button = res.find(MessageTemplates.BUTTON_LOGIN_PROMPT) != -1
    is_login_submission = res.find(MessageTemplates.AUTHORIZATION_MODAL_ID) != -1

    if is_login_submission:
        return make_login_submission(json_dict)

    if is_login_button:
        return make_login_button(json_dict, trigger_id)

    return HttpResponse(status=200)


@csrf_exempt
def event_hook(request):
    """
    Обработка сообщений в чате
    """
    json_dict = json.loads(request.body.decode('utf-8'))

    if json_dict['token'] != settings.VERIFICATION_TOKEN:
        return HttpResponse(status=403)

    if 'type' in json_dict:
        if json_dict['type'] == 'url_verification':
            response_dict = {'challenge': json_dict['challenge']}
            return JsonResponse(response_dict, safe=False)

    if 'event' not in json_dict:
        return HttpResponse(status=200)

    event_msg = json_dict['event']

    if 'bot_profile' in event_msg:
        return HttpResponse(status=200)

    if event_msg['type'] != 'message' or 'user' not in event_msg or 'channel' not in event_msg:
        return HttpResponse(status=200)

    slack_instance = SlackConnector()
    user = event_msg['user']
    channel = event_msg['channel']
    text = event_msg['text']
    client_msg_id = event_msg['client_msg_id']

    if SentMessages.objects.filter(client_msg_id=client_msg_id).exists():
        return HttpResponse(status=200)

    SentMessages.objects.create(client_msg_id=client_msg_id)

    if not BotUser.objects.filter(slack_user_id=user).exists():
        slack_instance.send_message(channel=channel, blocks=MessageTemplates.LOGIN_PROMPT)
        return HttpResponse(status=200)

    domain = BotUser.decrypt(BotUser.objects.get(slack_user_id=user).wikiworks_domain)

    ww = WikiworksConnector(domain)

    token = get_token(user, ww)

    if not token:
        return HttpResponse(status=200)

    results = ww.get_search_results(text, token['access'])
    show_search_results(results, channel, slack_instance)

    return HttpResponse(status=200)
