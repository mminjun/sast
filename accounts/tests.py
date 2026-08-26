"""인증·역할 시험 (TST-001, TST-002)."""

from django.contrib.auth import get_user_model
from django.core.cache import cache
from django.db import IntegrityError, transaction
from django.urls import reverse
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory, APITestCase, force_authenticate
from rest_framework.views import APIView

from accounts.models import Role
from accounts.permissions import IsAdminRole

User = get_user_model()

PASSWORD = 'sast-test-pw-9182'


class AdminOnlyView(APIView):
    """IsAdminRole 검증용 시험 전용 뷰 (실제 라우팅에는 등록하지 않는다)."""

    permission_classes = [IsAuthenticated, IsAdminRole]

    def get(self, request):
        return Response({'ok': True})


class AuthAPITestCase(APITestCase):
    """로그인 빈도 제한 카운터가 테스트 사이에 누적되지 않게 캐시를 비운다.

    ScopedRateThrottle은 캐시에 기록을 남기는데, 테스트는 같은 프로세스에서
    같은 클라이언트 IP로 실행되므로 비우지 않으면 무관한 테스트가 429로 깨진다.
    """

    def setUp(self):
        super().setUp()
        cache.clear()


class PasswordHashingTests(APITestCase):
    """SEC-001 — 비밀번호는 bcrypt로 저장된다."""

    def test_password_is_stored_with_bcrypt(self):
        user = User.objects.create_user(email='hash@example.com', password=PASSWORD)
        self.assertTrue(
            user.password.startswith('bcrypt_sha256$'),
            f'bcrypt로 저장되지 않았습니다: {user.password[:20]}',
        )

    def test_plaintext_password_is_not_stored(self):
        user = User.objects.create_user(email='plain@example.com', password=PASSWORD)
        user.refresh_from_db()
        self.assertNotIn(PASSWORD, user.password)
        self.assertTrue(user.check_password(PASSWORD))


class UserModelTests(APITestCase):
    """DAR-002, SEC-003 — 이메일 식별자와 역할 기본값."""

    def test_default_role_is_general_user(self):
        user = User.objects.create_user(email='default@example.com', password=PASSWORD)
        self.assertEqual(user.role, Role.USER)
        self.assertFalse(user.is_admin)

    def test_superuser_gets_admin_role(self):
        admin = User.objects.create_superuser(email='root@example.com', password=PASSWORD)
        self.assertEqual(admin.role, Role.ADMIN)
        self.assertTrue(admin.is_admin)

    def test_email_is_required(self):
        with self.assertRaises(ValueError):
            User.objects.create_user(email='', password=PASSWORD)


class EmailNormalizationTests(AuthAPITestCase):
    """SFR-001 — 이메일은 로그인 식별자이므로 대소문자를 구분하지 않는다."""

    def test_email_is_stored_lowercase(self):
        user = User.objects.create_user(email='  MiXeD@Example.COM ', password=PASSWORD)
        user.refresh_from_db()
        self.assertEqual(user.email, 'mixed@example.com')

    def test_duplicate_email_differing_only_in_case_is_rejected(self):
        User.objects.create_user(email='dup@example.com', password=PASSWORD)
        with self.assertRaises(IntegrityError), transaction.atomic():
            User.objects.create_user(email='DUP@example.com', password=PASSWORD)

    def test_login_is_case_insensitive(self):
        User.objects.create_user(email='case@example.com', password=PASSWORD)
        res = self.client.post(
            reverse('accounts:login'),
            {'email': 'CASE@Example.com', 'password': PASSWORD},
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('access', res.data)


class LoginTests(AuthAPITestCase):
    """TST-001 / SFR-001, SFR-002 — 이메일 로그인과 토큰 발급."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(email='login@example.com', password=PASSWORD)
        self.url = reverse('accounts:login')

    def test_login_with_valid_credentials_returns_tokens(self):
        res = self.client.post(self.url, {'email': self.user.email, 'password': PASSWORD})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('access', res.data)
        self.assertIn('refresh', res.data)

    def test_login_with_wrong_password_is_rejected(self):
        res = self.client.post(self.url, {'email': self.user.email, 'password': 'wrong-pw'})
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_login_response_leaks_no_password(self):
        """SEC-006 — 응답 본문에 비밀번호·해시가 실리지 않는다."""
        res = self.client.post(self.url, {'email': self.user.email, 'password': PASSWORD})
        body = str(res.data)
        self.assertNotIn(PASSWORD, body)
        self.assertNotIn('bcrypt_sha256$', body)


class LoginThrottleTests(AuthAPITestCase):
    """SEC-001 보완 — 온라인 무차별 대입은 빈도 제한으로 막는다."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(email='brute@example.com', password=PASSWORD)
        self.url = reverse('accounts:login')

    def test_repeated_failed_logins_are_throttled(self):
        for attempt in range(5):
            res = self.client.post(self.url, {'email': self.user.email, 'password': 'wrong-pw'})
            self.assertEqual(
                res.status_code, status.HTTP_401_UNAUTHORIZED,
                f'{attempt + 1}번째 시도는 아직 제한 대상이 아니어야 합니다.',
            )

        blocked = self.client.post(self.url, {'email': self.user.email, 'password': 'wrong-pw'})
        self.assertEqual(blocked.status_code, status.HTTP_429_TOO_MANY_REQUESTS)

    def test_throttle_also_blocks_correct_password(self):
        """제한에 걸린 뒤에는 올바른 비밀번호도 통과하지 못한다."""
        for _ in range(5):
            self.client.post(self.url, {'email': self.user.email, 'password': 'wrong-pw'})

        res = self.client.post(self.url, {'email': self.user.email, 'password': PASSWORD})
        self.assertEqual(res.status_code, status.HTTP_429_TOO_MANY_REQUESTS)


class AuthenticationRequiredTests(APITestCase):
    """SEC-002 — 인증 없이는 보호 자원에 접근할 수 없다."""

    def test_me_requires_authentication(self):
        res = self.client.get(reverse('accounts:me'))
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_me_returns_authenticated_user(self):
        user = User.objects.create_user(email='me@example.com', password=PASSWORD)
        self.client.force_authenticate(user=user)
        res = self.client.get(reverse('accounts:me'))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['email'], user.email)
        self.assertEqual(res.data['role'], Role.USER)
        self.assertNotIn('password', res.data)


class RolePermissionTests(APITestCase):
    """TST-002 / SFR-003, SEC-003, SEC-004 — 일반 사용자는 관리자 기능에 접근할 수 없다."""

    def setUp(self):
        self.factory = APIRequestFactory()
        self.view = AdminOnlyView.as_view()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.member = User.objects.create_user(email='member@example.com', password=PASSWORD)

    def _get(self, user):
        request = self.factory.get('/admin-only/')
        force_authenticate(request, user=user)
        return self.view(request)

    def test_admin_is_allowed(self):
        self.assertEqual(self._get(self.admin).status_code, status.HTTP_200_OK)

    def test_general_user_is_forbidden(self):
        self.assertEqual(self._get(self.member).status_code, status.HTTP_403_FORBIDDEN)

    def test_role_is_read_from_db_not_token(self):
        """역할을 강등하면 즉시 차단된다 — 인가는 DB의 현재 값으로 판단한다."""
        self.assertEqual(self._get(self.admin).status_code, status.HTTP_200_OK)
        self.admin.role = Role.USER
        self.admin.save(update_fields=['role'])
        self.admin.refresh_from_db()
        self.assertEqual(self._get(self.admin).status_code, status.HTTP_403_FORBIDDEN)


class LogoutTests(AuthAPITestCase):
    """SFR-002 — 로그아웃한 refresh 토큰은 재사용할 수 없다."""

    def setUp(self):
        super().setUp()
        self.user = User.objects.create_user(email='logout@example.com', password=PASSWORD)
        self.refresh = self._login(self.user.email)
        self.client.force_authenticate(user=self.user)

    def _login(self, email):
        res = self.client.post(
            reverse('accounts:login'), {'email': email, 'password': PASSWORD},
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        return res.data['refresh']

    def test_logout_blacklists_refresh_token(self):
        res = self.client.post(reverse('accounts:logout'), {'refresh': self.refresh})
        self.assertEqual(res.status_code, status.HTTP_205_RESET_CONTENT)

        reuse = self.client.post(reverse('accounts:refresh'), {'refresh': self.refresh})
        self.assertEqual(reuse.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_logout_without_refresh_token_is_rejected(self):
        res = self.client.post(reverse('accounts:logout'), {})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_cannot_blacklist_another_users_token(self):
        """SEC-005 — 타인의 refresh 토큰으로 강제 로그아웃시킬 수 없다."""
        self.client.force_authenticate(user=None)
        victim = User.objects.create_user(email='victim@example.com', password=PASSWORD)
        victim_refresh = self._login(victim.email)

        # 공격자는 자신으로 인증한 채 피해자의 토큰을 폐기하려 시도한다.
        self.client.force_authenticate(user=self.user)
        res = self.client.post(reverse('accounts:logout'), {'refresh': victim_refresh})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

        # 피해자의 토큰은 그대로 살아 있어야 한다.
        self.client.force_authenticate(user=None)
        still_valid = self.client.post(
            reverse('accounts:refresh'), {'refresh': victim_refresh},
        )
        self.assertEqual(still_valid.status_code, status.HTTP_200_OK)

    def test_invalid_and_foreign_tokens_return_same_response(self):
        """SEC-006 — 실패 사유가 응답으로 드러나지 않는다."""
        garbage = self.client.post(reverse('accounts:logout'), {'refresh': 'not-a-token'})
        missing = self.client.post(reverse('accounts:logout'), {})
        self.assertEqual(garbage.status_code, missing.status_code)
        self.assertEqual(garbage.data, missing.data)
