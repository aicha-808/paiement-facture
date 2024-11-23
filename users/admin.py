from django.contrib import admin

# Register your models here.
from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import CustomUser

@admin.register(CustomUser)
class CustomUserAdmin(UserAdmin):
    model = CustomUser
    list_display = ('name', 'phone_number', 'is_staff', 'is_active')
    search_fields = ('name', 'phone_number')
    ordering = ('phone_number',)
    fieldsets = (
        (None, {'fields': ('name', 'phone_number', 'password')}),
        ('Permissions', {'fields': ('is_staff', 'is_active', 'is_superuser', 'groups', 'user_permissions')}),
        ('Important dates', {'fields': ('last_login',)}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('name', 'phone_number', 'password1', 'password2', 'is_staff', 'is_active'),
        }),
    )
