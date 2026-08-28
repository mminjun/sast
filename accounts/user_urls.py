"""관리자용 사용자 관리 URL (SEC-003).

인증 경로(/api/auth/, accounts/urls.py)와 분리해 /api/users/로 노출한다.
<int:pk> 컨버터가 비숫자 pk를 URL 매칭 단계에서 404로 거른다 —
ProjectViewSet의 lookup_value_regex=r'\\d+'와 같은 원칙 (SEC-006).
"""

from django.urls import path

from .views import UserDetailView, UserListCreateView

app_name = 'users'

urlpatterns = [
    path('', UserListCreateView.as_view(), name='user-list'),
    path('<int:pk>/', UserDetailView.as_view(), name='user-detail'),
]
