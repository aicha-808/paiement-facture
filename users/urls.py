from django.urls import path
from .views import delete_user, login, logout_view, register_user, request_password_reset, reset_password, update_user

urlpatterns = [
    path('api/login/', login, name='login'),
    path('api/register/', register_user, name='register'),
    path('api/request-password-reset/', request_password_reset, name='request_reset_password'),
    path('api/reset-password/', reset_password, name='reset_password'),
    path('api/logout/', logout_view, name='logout'),
    path('api/delete-user/<str:id>/', delete_user, name='delete_user'),
    path('api/update-user/<str:id>/', update_user, name='update_user'),
]
