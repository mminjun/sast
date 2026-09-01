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
from analysis.models import AnalysisRun
from projects.models import Project, ProjectMember

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


def _detail_url(pk):
    return reverse('users:user-detail', kwargs={'pk': pk})


class UserAdminApiPermissionTests(APITestCase):
    """TST-002 / SEC-002, SEC-003 — 사용자 관리 API는 관리자 전용이다."""

    def setUp(self):
        self.admin = User.objects.create_user(
            email='uadmin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.member = User.objects.create_user(email='umember@example.com', password=PASSWORD)
        self.target = User.objects.create_user(email='utarget@example.com', password=PASSWORD)
        self.list_url = reverse('users:user-list')

    def _all_requests(self, pk):
        return [
            self.client.get(self.list_url),
            self.client.post(self.list_url, {'email': 'x@example.com', 'password': PASSWORD}),
            self.client.delete(_detail_url(pk)),
            self.client.patch(_detail_url(pk), {'is_active': False}, format='json'),
        ]

    def test_unauthenticated_requests_are_rejected(self):
        for res in self._all_requests(self.target.pk):
            self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_general_user_gets_uniform_403(self):
        """SEC-006 — 존재·미존재 id의 응답이 같아 계정 존재를 떠볼 수 없다."""
        self.client.force_authenticate(user=self.member)
        responses = self._all_requests(self.target.pk) + self._all_requests(999999)
        for res in responses:
            self.assertEqual(res.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(
            len({str(res.data) for res in responses}), 1,
            '응답 본문이 id에 따라 달라지면 존재 여부가 노출됩니다.',
        )

    def test_demoted_admin_is_forbidden_immediately(self):
        """인가는 토큰이 아니라 DB의 현재 역할로 판단한다 (SEC-003)."""
        self.client.force_authenticate(user=self.admin)
        self.assertEqual(self.client.get(self.list_url).status_code, status.HTTP_200_OK)
        self.admin.role = Role.USER
        self.admin.save(update_fields=['role'])
        self.assertEqual(self.client.get(self.list_url).status_code, status.HTTP_403_FORBIDDEN)


class UserListApiTests(APITestCase):
    """SEC-006 — 목록은 id·email·name·role·is_active만 노출한다."""

    def setUp(self):
        self.admin = User.objects.create_user(
            email='ladmin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.client.force_authenticate(user=self.admin)

    def test_list_exposes_exact_fields_only(self):
        User.objects.create_user(email='row@example.com', password=PASSWORD)
        res = self.client.get(reverse('users:user-list'))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(len(res.data), 2)
        for row in res.data:
            self.assertEqual(
                set(row.keys()),
                {'id', 'email', 'name', 'role', 'is_active', 'projects', 'has_history'},
            )

    def test_list_includes_assigned_projects(self):
        """할당 프로젝트는 id·name만 — 목록 화면 표시용 읽기 전용 (SFR-005 참조)."""
        member = User.objects.create_user(email='pm@example.com', password=PASSWORD)
        project = Project.objects.create(name='P1', created_by=self.admin)
        ProjectMember.objects.create(project=project, user=member, assigned_by=self.admin)

        res = self.client.get(reverse('users:user-list'))
        row = next(r for r in res.data if r['email'] == 'pm@example.com')
        self.assertEqual(row['projects'], [{'id': project.pk, 'name': 'P1'}])
        # 할당이 없는 계정은 빈 목록이다.
        admin_row = next(r for r in res.data if r['email'] == self.admin.email)
        self.assertEqual(admin_row['projects'], [])

    def test_has_history_matches_delete_protection(self):
        """has_history는 삭제를 막는 PROTECT 참조와 같은 기준이다 (DAR-010).

        True인 계정의 DELETE는 409, False인 계정의 DELETE는 204여야 안내가
        거짓이 되지 않는다.
        """
        creator = User.objects.create_user(email='creator@example.com', password=PASSWORD)
        runner = User.objects.create_user(email='runner@example.com', password=PASSWORD)
        clean = User.objects.create_user(email='clean@example.com', password=PASSWORD)
        project = Project.objects.create(name='P', created_by=creator)
        AnalysisRun.objects.create(
            project=project, created_by=runner, original_filename='src.zip',
        )

        res = self.client.get(reverse('users:user-list'))
        flags = {row['email']: row['has_history'] for row in res.data}
        self.assertTrue(flags['creator@example.com'])   # Project.created_by
        self.assertTrue(flags['runner@example.com'])    # AnalysisRun.created_by
        self.assertFalse(flags['clean@example.com'])

        self.assertEqual(
            self.client.delete(_detail_url(creator.pk)).status_code,
            status.HTTP_409_CONFLICT,
        )
        self.assertEqual(
            self.client.delete(_detail_url(clean.pk)).status_code,
            status.HTTP_204_NO_CONTENT,
        )

    def test_has_history_covers_assigner(self):
        """할당 감사 기록(assigned_by)도 이력이다."""
        assigner = User.objects.create_user(
            email='assigner@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        member = User.objects.create_user(email='mem@example.com', password=PASSWORD)
        project = Project.objects.create(name='P', created_by=self.admin)
        ProjectMember.objects.create(project=project, user=member, assigned_by=assigner)

        res = self.client.get(reverse('users:user-list'))
        flags = {row['email']: row['has_history'] for row in res.data}
        self.assertTrue(flags['assigner@example.com'])

    def test_list_includes_inactive_users(self):
        User.objects.create_user(email='off@example.com', password=PASSWORD, is_active=False)
        res = self.client.get(reverse('users:user-list'))
        inactive = [row for row in res.data if row['email'] == 'off@example.com']
        self.assertEqual(len(inactive), 1)
        self.assertFalse(inactive[0]['is_active'])


class UserCreateApiTests(AuthAPITestCase):
    """SEC-003, SEC-001 — 생성 계정은 서버가 USER로 강제하고 bcrypt로 저장한다."""

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user(
            email='cadmin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.client.force_authenticate(user=self.admin)
        self.url = reverse('users:user-list')

    def test_created_user_has_user_role(self):
        res = self.client.post(self.url, {'email': 'new@example.com', 'password': PASSWORD})
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(set(res.data.keys()), {'id', 'email', 'name', 'role', 'is_active'})
        self.assertEqual(res.data['role'], Role.USER)
        self.assertTrue(res.data['is_active'])

    def test_role_in_request_body_is_ignored(self):
        """클라이언트가 role을 보내도 관리자 계정이 만들어지지 않는다 (SEC-003)."""
        res = self.client.post(
            self.url,
            {'email': 'sneaky@example.com', 'password': PASSWORD, 'role': Role.ADMIN},
        )
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['role'], Role.USER)
        self.assertEqual(User.objects.get(email='sneaky@example.com').role, Role.USER)

    def test_is_active_in_request_body_is_ignored(self):
        res = self.client.post(
            self.url,
            {'email': 'active@example.com', 'password': PASSWORD, 'is_active': False},
            format='json',
        )
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertTrue(res.data['is_active'])

    def test_name_is_optional_and_stored(self):
        """name은 선택 입력 — 주면 저장되고, 안 주면 빈 문자열이다."""
        res = self.client.post(
            self.url, {'email': 'named@example.com', 'password': PASSWORD, 'name': '홍길동'},
        )
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['name'], '홍길동')

        res = self.client.post(self.url, {'email': 'noname@example.com', 'password': PASSWORD})
        self.assertEqual(res.status_code, status.HTTP_201_CREATED)
        self.assertEqual(res.data['name'], '')

    def test_password_is_stored_with_bcrypt(self):
        self.client.post(self.url, {'email': 'bc@example.com', 'password': PASSWORD})
        user = User.objects.get(email='bc@example.com')
        self.assertTrue(user.password.startswith('bcrypt_sha256$'))
        self.assertTrue(user.check_password(PASSWORD))

    def test_duplicate_email_is_rejected_case_insensitively(self):
        User.objects.create_user(email='dupe@example.com', password=PASSWORD)
        res = self.client.post(self.url, {'email': 'DUPE@Example.com', 'password': PASSWORD})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_weak_passwords_are_rejected(self):
        """AUTH_PASSWORD_VALIDATORS가 실제로 적용된다 (SEC-001)."""
        cases = {
            'short': 'a1b2c3!',          # 8자 미만
            'common': 'password',        # 흔한 비밀번호
            'numeric': '8473921805',     # 숫자만
            'similar': 'weakuser',       # 이메일과 유사
        }
        for name, password in cases.items():
            res = self.client.post(
                self.url, {'email': 'weakuser@example.com', 'password': password},
            )
            self.assertEqual(
                res.status_code, status.HTTP_400_BAD_REQUEST,
                f'{name} 비밀번호가 통과했습니다.',
            )
        self.assertFalse(User.objects.filter(email='weakuser@example.com').exists())

    def test_invalid_email_and_missing_fields_are_rejected(self):
        for body in (
            {'email': 'not-an-email', 'password': PASSWORD},
            {'password': PASSWORD},
            {'email': 'nopw@example.com'},
        ):
            res = self.client.post(self.url, body)
            self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_created_user_can_login(self):
        self.client.post(self.url, {'email': 'canlogin@example.com', 'password': PASSWORD})
        self.client.force_authenticate(user=None)
        res = self.client.post(
            reverse('accounts:login'),
            {'email': 'canlogin@example.com', 'password': PASSWORD},
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertIn('access', res.data)


class UserDeleteApiTests(APITestCase):
    """SEC-003, DAR-010 — 물리 삭제는 이력 없는 계정만, 보호 참조는 409."""

    def setUp(self):
        self.admin = User.objects.create_user(
            email='dadmin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.target = User.objects.create_user(email='dtarget@example.com', password=PASSWORD)
        self.client.force_authenticate(user=self.admin)

    def test_user_without_history_is_deleted(self):
        res = self.client.delete(_detail_url(self.target.pk))
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(User.objects.filter(pk=self.target.pk).exists())

    def test_membership_only_user_is_deleted_with_memberships(self):
        """멤버십(CASCADE)은 이력이 아니다 — 계정과 함께 지워진다."""
        project = Project.objects.create(name='P', created_by=self.admin)
        ProjectMember.objects.create(project=project, user=self.target, assigned_by=self.admin)
        res = self.client.delete(_detail_url(self.target.pk))
        self.assertEqual(res.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(ProjectMember.objects.filter(project=project).exists())
        self.assertTrue(Project.objects.filter(pk=project.pk).exists())

    def test_project_creator_cannot_be_deleted(self):
        Project.objects.create(name='P', created_by=self.target)
        res = self.client.delete(_detail_url(self.target.pk))
        self.assertEqual(res.status_code, status.HTTP_409_CONFLICT)
        self.assertTrue(User.objects.filter(pk=self.target.pk).exists())

    def test_analysis_runner_cannot_be_deleted(self):
        project = Project.objects.create(name='P', created_by=self.admin)
        AnalysisRun.objects.create(
            project=project, created_by=self.target, original_filename='src.zip',
        )
        res = self.client.delete(_detail_url(self.target.pk))
        self.assertEqual(res.status_code, status.HTTP_409_CONFLICT)

    def test_assigner_cannot_be_deleted(self):
        """할당 감사 기록(assigned_by)도 보호 참조다."""
        other_admin = User.objects.create_user(
            email='dadmin2@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        project = Project.objects.create(name='P', created_by=self.admin)
        ProjectMember.objects.create(project=project, user=self.target, assigned_by=other_admin)
        res = self.client.delete(_detail_url(other_admin.pk))
        self.assertEqual(res.status_code, status.HTTP_409_CONFLICT)

    def test_cannot_delete_self(self):
        res = self.client.delete(_detail_url(self.admin.pk))
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())

    def test_last_active_admin_cannot_be_deleted(self):
        """관리자 0명 상태를 만들 수 없다 — 비활성 관리자가 유일한 활성 관리자를
        지우는 경합 상황을 직렬로 재현한다."""
        inactive_admin = User.objects.create_user(
            email='ghost@example.com', password=PASSWORD, role=Role.ADMIN, is_active=False,
        )
        self.client.force_authenticate(user=inactive_admin)
        res = self.client.delete(_detail_url(self.admin.pk))
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertTrue(User.objects.filter(pk=self.admin.pk).exists())

    def test_missing_user_returns_404(self):
        self.assertEqual(
            self.client.delete(_detail_url(999999)).status_code, status.HTTP_404_NOT_FOUND,
        )

    def test_non_numeric_pk_returns_404(self):
        """비숫자 pk는 URL 매칭 단계에서 걸러진다 (SEC-006)."""
        self.assertEqual(
            self.client.delete('/api/users/abc/').status_code, status.HTTP_404_NOT_FOUND,
        )


class UserDeactivateApiTests(AuthAPITestCase):
    """SEC-003 — 비활성화는 즉시 효력이 있고, 자기 자신·마지막 관리자는 막는다."""

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user(
            email='padmin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.target = User.objects.create_user(email='ptarget@example.com', password=PASSWORD)
        self.client.force_authenticate(user=self.admin)

    def _patch(self, pk, body):
        return self.client.patch(_detail_url(pk), body, format='json')

    def test_deactivate_and_reactivate(self):
        res = self._patch(self.target.pk, {'is_active': False})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertFalse(res.data['is_active'])

        for _ in range(2):  # 재활성화는 멱등
            res = self._patch(self.target.pk, {'is_active': True})
            self.assertEqual(res.status_code, status.HTTP_200_OK)
            self.assertTrue(res.data['is_active'])

    def test_cannot_deactivate_self(self):
        res = self._patch(self.admin.pk, {'is_active': False})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)
        self.admin.refresh_from_db()
        self.assertTrue(self.admin.is_active)

    def test_last_active_admin_cannot_be_deactivated(self):
        inactive_admin = User.objects.create_user(
            email='pghost@example.com', password=PASSWORD, role=Role.ADMIN, is_active=False,
        )
        self.client.force_authenticate(user=inactive_admin)
        res = self._patch(self.admin.pk, {'is_active': False})
        self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_other_fields_in_patch_are_ignored(self):
        """is_active 외 필드는 구조적으로 도달 불가 — 특히 password 해시 불변."""
        before_hash = User.objects.get(pk=self.target.pk).password
        res = self._patch(
            self.target.pk,
            {'is_active': False, 'role': Role.ADMIN,
             'email': 'stolen@example.com', 'password': 'evil-pw-123'},
        )
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.target.refresh_from_db()
        self.assertEqual(self.target.role, Role.USER)
        self.assertEqual(self.target.email, 'ptarget@example.com')
        self.assertEqual(self.target.password, before_hash)

    def test_missing_or_invalid_is_active_is_rejected(self):
        for body in ({}, {'is_active': 'maybe'}):
            res = self._patch(self.target.pk, body)
            self.assertEqual(res.status_code, status.HTTP_400_BAD_REQUEST)

    def test_patch_updates_name_without_touching_is_active(self):
        res = self._patch(self.target.pk, {'name': '김분석'})
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        self.assertEqual(res.data['name'], '김분석')
        self.target.refresh_from_db()
        self.assertEqual(self.target.name, '김분석')
        self.assertTrue(self.target.is_active)

    def test_deactivation_revokes_issued_access_token(self):
        """발급된 access 토큰도 다음 요청부터 401 — simplejwt가 DB의 is_active를 본다."""
        login = self.client.post(
            reverse('accounts:login'),
            {'email': self.target.email, 'password': PASSWORD},
        )
        access = login.data['access']

        me_client = self.client_class(HTTP_AUTHORIZATION=f'Bearer {access}')
        self.assertEqual(
            me_client.get(reverse('accounts:me')).status_code, status.HTTP_200_OK,
        )

        self._patch(self.target.pk, {'is_active': False})
        self.assertEqual(
            me_client.get(reverse('accounts:me')).status_code, status.HTTP_401_UNAUTHORIZED,
        )

    def test_inactive_user_cannot_login(self):
        self._patch(self.target.pk, {'is_active': False})
        res = self.client.post(
            reverse('accounts:login'),
            {'email': self.target.email, 'password': PASSWORD},
        )
        self.assertEqual(res.status_code, status.HTTP_401_UNAUTHORIZED)
