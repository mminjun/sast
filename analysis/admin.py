"""Django admin 등록 (SFR-008, SFR-015)."""

from django.contrib import admin

from .models import AnalysisRun


@admin.register(AnalysisRun)
class AnalysisRunAdmin(admin.ModelAdmin):
    list_display = ('project', 'status', 'created_by', 'created_at', 'finished_at')
    list_filter = ('status', 'project')
    search_fields = ('project__name', 'original_filename')
    readonly_fields = ('workspace_id', 'created_at', 'started_at', 'finished_at')
