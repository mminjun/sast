"""프로젝트 엔드포인트 (SFR-004, SFR-005, SFR-006)."""

from django.urls import include, path
from rest_framework.routers import SimpleRouter

from .views import ProjectViewSet

app_name = 'projects'

# DefaultRouter 대신 SimpleRouter — DefaultRouter는 '' 경로에 API 루트 뷰를 만들어
# /api/ 를 이 앱이 선점한다. 뒤에 analysis·catalog가 같은 prefix에 붙을 예정이므로 피한다.
router = SimpleRouter()
# ViewSet에 queryset 속성 대신 get_queryset()을 쓰므로 basename을 명시한다.
router.register('projects', ProjectViewSet, basename='project')

urlpatterns = [
    path('', include(router.urls)),
]
