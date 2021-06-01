from django.urls import path

from actions.views import event_hook, interactivity_hook

urlpatterns = [
    path('event/hook/', event_hook, name='event_hook'),
    path('interactivity/hook/', interactivity_hook, name='interactivity_hook'),
]
