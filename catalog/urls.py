"""진단 기준·결과 엔드포인트 (SFR-013, SFR-014, SFR-016, SFR-017)."""

from django.urls import path

from .views import (
    CatalogSummaryView,
    DiagnosticRuleDetailView,
    DiagnosticRuleListView,
    ProjectRunChangesView,
    RunDiffView,
    RunFindingListView,
    RunFindingReingestView,
    RunFindingSummaryView,
)

app_name = 'catalog'

urlpatterns = [
    # 진단 기준 49개 — 프로젝트에 딸리지 않은 공통 기준 문서
    path('catalog/rules/', DiagnosticRuleListView.as_view(), name='rule-list'),
    path('catalog/summary/', CatalogSummaryView.as_view(), name='catalog-summary'),
    path('catalog/rules/<str:code>/', DiagnosticRuleDetailView.as_view(), name='rule-detail'),

    # 진단 결과 — 자원은 catalog 책임이지만 URL은 실행 아래에 중첩된다.
    # analysis/urls.py의 analysis-runs 경로와 세그먼트가 겹치지 않는다(뒤에 findings가 붙는다).
    path('analysis-runs/<int:run_id>/findings/',
         RunFindingListView.as_view(), name='run-finding-list'),
    path('analysis-runs/<int:run_id>/findings/summary/',
         RunFindingSummaryView.as_view(), name='run-finding-summary'),
    path('analysis-runs/<int:run_id>/findings/reingest/',
         RunFindingReingestView.as_view(), name='run-finding-reingest'),
    # 실행 간 비교 — findings와 같은 이유로 자원은 catalog 책임이다.
    path('analysis-runs/<int:run_id>/diff/',
         RunDiffView.as_view(), name='run-diff'),
    # 실행 이력의 직전 대비 변화량 — analysis 목록 API를 확장하지 않는 이유는
    # catalog/views.py ProjectRunChangesView 참고.
    path('projects/<int:project_id>/run-changes/',
         ProjectRunChangesView.as_view(), name='project-run-changes'),
]
