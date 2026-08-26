"""인증 관련 뷰 (SFR-001, SFR-002, SEC-002).

로그인·갱신은 simplejwt가 제공하는 뷰를 그대로 쓴다 (accounts/urls.py 참조).
USERNAME_FIELD가 email이므로 별도 커스터마이징 없이 이메일로 인증된다.
"""

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.exceptions import TokenError
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework_simplejwt.views import TokenObtainPairView

from .serializers import UserSerializer


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
