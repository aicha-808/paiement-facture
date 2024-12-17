from django.urls import path
from .views import CustomUserListView, delete_user, login, logout_view, register_user, request_password_reset, reset_password, update_user

urlpatterns = [
    path('login/', login, name='login'),
    path('register/', register_user, name='register'),
    path('request-password-reset/', request_password_reset, name='request_reset_password'),
    path('reset-password/', reset_password, name='reset_password'),
    path('logout/', logout_view, name='logout'),
    path('delete-user/<str:id>/', delete_user, name='delete_user'),
    path('update-user/<str:id>/', update_user, name='update_user'),
    path('users/', CustomUserListView.as_view(), name='users_list')
]
