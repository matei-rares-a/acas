from django.urls import path
from . import views

urlpatterns = [
    path('register', views.register, name='register'),
    path('commit', views.commit, name='commit'),
    path('verify', views.verify, name='verify'),
    path('forgetme', views.forgetme, name='forgetme'),
    path('health', views.health, name='health'),
]
