"""분석 실행 엔드포인트 (SFR-007~009)."""

from django.urls import path

from .views import AnalysisRunDetailView, AnalysisRunExecuteView, ProjectAnalysisRunsView

app_name = 'analysis'

urlpatterns = [
    # projects 앱 라우트(api/projects/<pk>/)와 세그먼트가 겹치지 않는다 — 뒤에 추가 경로가 붙는다.
    path('projects/<int:project_id>/analysis-runs/', ProjectAnalysisRunsView.as_view(), name='analysis-run-list'),
    path('analysis-runs/<int:pk>/', AnalysisRunDetailView.as_view(), name='analysis-run-detail'),
    path('analysis-runs/<int:pk>/execute/', AnalysisRunExecuteView.as_view(), name='analysis-run-execute'),
]
