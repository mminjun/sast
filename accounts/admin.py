"""Django admin 등록 (SEC-003)."""

from django.contrib import admin
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin

from .models import User


@admin.register(User)
class UserAdmin(BaseUserAdmin):
    """기본 UserAdmin은 username 필드를 참조하므로 email 기준으로 교체한다."""

    ordering = ('email',)
    list_display = ('email', 'role', 'is_active', 'is_staff')
    list_filter = ('role', 'is_active', 'is_staff')
    search_fields = ('email',)

    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('권한', {'fields': ('role', 'is_active', 'is_staff', 'is_superuser',
                             'groups', 'user_permissions')}),
        ('기록', {'fields': ('last_login', 'date_joined')}),
    )
    add_fieldsets = (
        (None, {
            'classes': ('wide',),
            'fields': ('email', 'password1', 'password2', 'role'),
        }),
    )
