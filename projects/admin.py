"""Django admin 등록 (SFR-004, SFR-005)."""

from django.contrib import admin

from .models import Project, ProjectMember


class ProjectMemberInline(admin.TabularInline):
    """프로젝트 화면에서 할당 현황을 함께 본다."""

    model = ProjectMember
    extra = 0
    autocomplete_fields = ('user', 'assigned_by')
    readonly_fields = ('assigned_at',)


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ('name', 'created_by', 'created_at')
    search_fields = ('name',)
    readonly_fields = ('created_at', 'updated_at')
    inlines = (ProjectMemberInline,)


@admin.register(ProjectMember)
class ProjectMemberAdmin(admin.ModelAdmin):
    list_display = ('project', 'user', 'assigned_by', 'assigned_at')
    list_filter = ('project',)
    search_fields = ('project__name', 'user__email')
    readonly_fields = ('assigned_at',)
