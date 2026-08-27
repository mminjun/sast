"""진단 기준·결과 엔드포인트 (SFR-013, SFR-014, SFR-016, SFR-017)."""

from django.urls import path

from .views import (
    CatalogSummaryView,
    DiagnosticRuleDetailView,
    DiagnosticRuleListView,
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
]
