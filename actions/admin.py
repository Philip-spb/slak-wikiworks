from django.contrib import admin

from actions.models import BotUser, SentMessages


class BotUserAdmin(admin.ModelAdmin):
    list_display = ('id', 'slack_user_id', 'wikiworks_login', 'wikiworks_password', 'wikiworks_domain')
    list_display_links = ('id', 'slack_user_id')
    search_fields = ('slack_user_id',)
    fields = ('slack_user_id', 'wikiworks_login', 'wikiworks_password', 'wikiworks_domain')


class SentMessagesAdmin(admin.ModelAdmin):
    list_display = ('id', 'client_msg_id',)
    search_fields = ('client_msg_id',)
    fields = ('client_msg_id',)


admin.site.register(BotUser, BotUserAdmin)
admin.site.register(SentMessages, SentMessagesAdmin)
