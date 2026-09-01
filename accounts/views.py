"""인증·사용자 관리 뷰 (SFR-001, SFR-002, SEC-002, SEC-003).

로그인·갱신은 simplejwt가 제공하는 뷰를 그대로 쓴다 (accounts/urls.py 참조).
USERNAME_FIELD가 email이므로 별도 커스터마이징 없이 이메일로 인증된다.
사용자 관리(목록·생성·삭제·활성 토글)는 관리자 전용이다 (accounts/user_urls.py).
"""

from django.db import transaction
from django.db.models import Exists, OuterRef, Q
from django.db.models.deletion import ProtectedError
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from analysis.models import AnalysisRun
from projects.models import Project, ProjectMember

from .models import Role, User
from .permissions import IsAdminRole
from .serializers import (
    UserCreateSerializer,
    UserListSerializer,
    UserSerializer,
    UserUpdateSerializer,
)


class LoginView(TokenObtainPairView):
    """이메일+비밀번호 로그인 (SFR-001).

    동작은 simplejwt 기본 뷰 그대로이고, 무차별 대입을 막기 위한
    호출 빈도 제한만 붙인다 (settings.DEFAULT_THROTTLE_RATES['login']).
    """

    throttle_scope = 'login'


class MeView(APIView):
    """현재 로그인한 사용자 정보 (SFR-001).

    클라이언트가 보낸 ID가 아니라 인증된 토큰이 가리키는 사용자만 반환한다.
    """

    def get(self, request):
        return Response(UserSerializer(request.user).data)


class LogoutView(APIView):
    """refresh 토큰을 blacklist에 등록해 재사용을 막는다 (SFR-002)."""

    # 실패 사유(형식 오류/이미 폐기/타인 토큰)를 구분해서 알려주지 않는다 —
    # 응답 차이가 토큰 유효성 확인 수단이 되지 않게 한다 (SEC-006).
    INVALID = {'detail': '유효하지 않은 토큰입니다.'}

    def post(self, request):
        refresh = request.data.get('refresh')
        if not refresh:
            return Response(self.INVALID, status=status.HTTP_400_BAD_REQUEST)

        try:
            token = RefreshToken(refresh)
        except TokenError:
            return Response(self.INVALID, status=status.HTTP_400_BAD_REQUEST)

        # 서명·만료만으로는 "내 토큰"인지 알 수 없다. 타인의 refresh 토큰을
        # 폐기해 강제 로그아웃시키지 못하도록 소유자를 확인한다 (SEC-005).
        if str(token.get('user_id')) != str(request.user.pk):
            return Response(self.INVALID, status=status.HTTP_400_BAD_REQUEST)

        token.blacklist()
        return Response(status=status.HTTP_205_RESET_CONTENT)


class UserListCreateView(APIView):
    """관리자용 사용자 목록·생성 (SEC-003).

    자가 등록(회원가입)이 아니라 관리자 통제 모델의 UI화다 — 공개 가입
    경로는 여전히 존재하지 않는다 (docs/decisions.md).
    """

    permission_classes = [IsAuthenticated, IsAdminRole]

    def get(self, request):
        # has_history는 삭제를 막는 PROTECT 참조(활동 이력)와 같은 기준이어야
        # 한다 — True인데 삭제가 통과하거나 False인데 409가 나면 안내가 거짓이 된다.
        # prefetch — 사용자 수만큼 할당 프로젝트 쿼리가 늘지 않게 한다 (N+1 방지).
        users = (
            User.objects.order_by('id')
            .prefetch_related('projects')
            .annotate(
                has_history=Exists(Project.objects.filter(created_by=OuterRef('pk')))
                | Exists(AnalysisRun.objects.filter(created_by=OuterRef('pk')))
                | Exists(ProjectMember.objects.filter(assigned_by=OuterRef('pk')))
            )
        )
        return Response(UserListSerializer(users, many=True).data)

    def post(self, request):
        serializer = UserCreateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        user = serializer.save()
        return Response(UserSerializer(user).data, status=status.HTTP_201_CREATED)


class UserDetailView(APIView):
    """관리자용 계정 삭제·활성 상태·이름 변경 (SEC-003).

    삭제와 비활성화 모두 자기 자신·마지막 활성 관리자를 막는다 —
    관리 기능 접근 경로가 통째로 사라지는 상태를 방지한다.
    """

    permission_classes = [IsAuthenticated, IsAdminRole]

    FORBIDDEN_SELF = {'detail': '자기 자신은 삭제·비활성화할 수 없습니다.'}
    FORBIDDEN_LAST_ADMIN = {'detail': '마지막 활성 관리자는 삭제·비활성화할 수 없습니다.'}
    PROTECTED = {'detail': '활동 이력이 있어 삭제할 수 없습니다. 대신 비활성화하세요.'}

    def _locked_target(self, request, pk):
        """대상 행과 활성 관리자 전원을 잠그고 (target, error_response)를 돌려준다.

        대상만 잠그면 두 관리자가 서로를 동시에 제거해 관리자 0명이 되는
        경합이 남는다. 활성 관리자 전원을 pk 순서로 함께 잠가 마지막
        관리자 검사와 제거를 직렬화한다 (SEC-009와 같은 원칙).
        transaction.atomic() 안에서만 호출해야 한다.
        """
        locked = {
            user.pk: user
            for user in User.objects.select_for_update()
            .filter(Q(pk=pk) | Q(role=Role.ADMIN, is_active=True))
            .order_by('pk')
        }
        target = locked.get(pk)
        if target is None:
            return None, Response(status=status.HTTP_404_NOT_FOUND)
        if target.pk == request.user.pk:
            return None, Response(self.FORBIDDEN_SELF, status=status.HTTP_400_BAD_REQUEST)
        if target.role == Role.ADMIN and target.is_active:
            remaining = sum(
                1
                for user in locked.values()
                if user.role == Role.ADMIN and user.is_active and user.pk != target.pk
            )
            if remaining == 0:
                return None, Response(
                    self.FORBIDDEN_LAST_ADMIN, status=status.HTTP_400_BAD_REQUEST
                )
        return target, None

    def delete(self, request, pk):
        with transaction.atomic():
            target, error = self._locked_target(request, pk)
            if error is not None:
                return error
            try:
                # PROTECT 참조(프로젝트 생성·분석 실행·할당 기록)가 있으면
                # 수집 단계에서 ProtectedError가 난다 — SQL 실행 전이라
                # atomic 안에서 잡아도 트랜잭션이 오염되지 않는다.
                target.delete()
            except ProtectedError:
                return Response(self.PROTECTED, status=status.HTTP_409_CONFLICT)
        return Response(status=status.HTTP_204_NO_CONTENT)

    def patch(self, request, pk):
        serializer = UserUpdateSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        with transaction.atomic():
            if data.get('is_active') is False:
                target, error = self._locked_target(request, pk)
                if error is not None:
                    return error
            else:
                # 재활성화·이름 변경은 잠금 없이 단순 갱신 — 관리자 수가
                # 줄어드는 방향이 아니라 가드가 필요 없다. 멱등.
                target = User.objects.filter(pk=pk).first()
                if target is None:
                    return Response(status=status.HTTP_404_NOT_FOUND)
                if target.pk == request.user.pk:
                    return Response(
                        self.FORBIDDEN_SELF, status=status.HTTP_400_BAD_REQUEST
                    )
            for field, value in data.items():
                setattr(target, field, value)
            target.save(update_fields=list(data))
        # 비활성화 즉시 효력은 별도 코드가 필요 없다 — simplejwt가 매 요청
        # DB의 is_active를 확인하므로 발급된 access 토큰도 다음 요청부터 401이다.
        return Response(UserSerializer(target).data)
