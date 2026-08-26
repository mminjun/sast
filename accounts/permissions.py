"""역할 기반 권한 클래스 (SFR-003, SEC-003, SEC-004)."""

from rest_framework.permissions import BasePermission


class IsAdminRole(BasePermission):
    """관리자 전용 기능 접근 통제 (SEC-003).

    역할은 JWT 클레임이 아니라 DB에 저장된 현재 값으로 판단한다.
    토큰은 서명돼 있어도 발급 시점의 스냅샷이라, 역할이 강등된 사용자가
    토큰 만료 전까지 관리자로 통과할 수 있다.
    """

    message = '관리자 권한이 필요합니다.'

    def has_permission(self, request, view):
        user = request.user
        return bool(user and user.is_authenticated and user.is_admin)
