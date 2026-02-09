from django.urls import path
from . import views

urlpatterns = [
    path('commit', views.commit, name='commit'),
    path('verify', views.verify, name='verify'),
]
