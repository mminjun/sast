"""인증 엔드포인트 (SFR-001, SFR-002)."""

from django.urls import path
from rest_framework_simplejwt.views import TokenRefreshView

from .views import LoginView, LogoutView, MeView

app_name = 'accounts'

urlpatterns = [
    # simplejwt 기본 뷰를 그대로 사용한다 — 직접 짠 인증 코드를 줄이는 편이 안전하다.
    # 로그인만 빈도 제한을 위해 얇게 감싼다 (LoginView).
    path('login/', LoginView.as_view(), name='login'),
    path('refresh/', TokenRefreshView.as_view(), name='refresh'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('me/', MeView.as_view(), name='me'),
]
