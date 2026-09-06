"""프로젝트 접근·할당 시험 (TST-003, SFR-004~006, SEC-003~006).

핵심은 IDOR 방어다 — 일반 사용자가 URL에 임의의 project_id를 넣어도 할당되지 않은
프로젝트에는 도달할 수 없고, 그 응답이 '존재하지 않는 id'와 구별되지 않아야 한다.
"""

from django.contrib.auth import get_user_model
from django.core.exceptions import ValidationError
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import Role
from projects.exclude_paths import is_excluded
from projects.models import Project, ProjectMember

User = get_user_model()

PASSWORD = 'sast-test-pw-9182'

LIST_URL = reverse('projects:project-list')


def detail_url(project_id):
    return reverse('projects:project-detail', args=[project_id])


def members_url(project_id):
    return reverse('projects:project-members', args=[project_id])


def member_detail_url(project_id, user_id):
    return reverse('projects:project-member-detail', args=[project_id, user_id])


class ProjectTestCase(APITestCase):
    """관리자 1명, 일반 사용자 2명, 프로젝트 2개를 깔아둔다.

    - project_a: user_a에게 할당
    - project_b: 아무에게도 할당하지 않음 (user_a 기준 '미할당 프로젝트')
    """

    def setUp(self):
        super().setUp()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.user_a = User.objects.create_user(email='a@example.com', password=PASSWORD)
        self.user_b = User.objects.create_user(email='b@example.com', password=PASSWORD)

        self.project_a = Project.objects.create(name='할당된 프로젝트', created_by=self.admin)
        self.project_b = Project.objects.create(name='미할당 프로젝트', created_by=self.admin)

        ProjectMember.objects.create(
            project=self.project_a, user=self.user_a, assigned_by=self.admin,
        )

        # 존재하지 않는 것이 확실한 id — '미할당'과 '없음'의 응답을 비교하는 데 쓴다.
        self.missing_id = Project.objects.order_by('-pk').first().pk + 1000

    def login(self, user):
        self.client.force_authenticate(user=user)


class UnauthenticatedTests(ProjectTestCase):
    """SEC-002 — 인증 없이는 아무것도 열리지 않는다."""

    def test_list_requires_authentication(self):
        response = self.client.get(LIST_URL)
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_detail_requires_authentication(self):
        response = self.client.get(detail_url(self.project_a.pk))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class ProjectScopeTests(ProjectTestCase):
    """SFR-006, SEC-005 — 조회 범위는 DB의 할당 관계로 결정된다."""

    def test_user_list_shows_only_assigned_projects(self):
        self.login(self.user_a)
        response = self.client.get(LIST_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        ids = [row['id'] for row in response.data]
        self.assertEqual(ids, [self.project_a.pk])
        self.assertNotIn(self.project_b.pk, ids)

    def test_user_with_no_assignment_sees_empty_list(self):
        self.login(self.user_b)
        response = self.client.get(LIST_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data, [])

    def test_admin_sees_all_projects(self):
        self.login(self.admin)
        response = self.client.get(LIST_URL)

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertCountEqual(
            [row['id'] for row in response.data],
            [self.project_a.pk, self.project_b.pk],
        )

    def test_user_can_read_assigned_project(self):
        self.login(self.user_a)
        response = self.client.get(detail_url(self.project_a.pk))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['id'], self.project_a.pk)


class IdorDefenseTests(ProjectTestCase):
    """SEC-005, SEC-006 — 시연 핵심. URL의 project_id를 신뢰하지 않는다."""

    def test_user_cannot_read_unassigned_project_by_id(self):
        """미할당 프로젝트의 id를 직접 넣어도 도달할 수 없다 (IDOR 방어)."""
        self.login(self.user_a)
        response = self.client.get(detail_url(self.project_b.pk))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unassigned_and_missing_project_are_indistinguishable(self):
        """미할당 프로젝트와 존재하지 않는 프로젝트의 응답이 같다 (존재 은닉)."""
        self.login(self.user_a)
        unassigned = self.client.get(detail_url(self.project_b.pk))
        missing = self.client.get(detail_url(self.missing_id))

        self.assertEqual(unassigned.status_code, missing.status_code)
        self.assertEqual(unassigned.data, missing.data)

    def test_revoking_assignment_blocks_access_immediately(self):
        """할당 해제 즉시 차단된다 — 토큰 재발급을 기다리지 않는다."""
        self.login(self.user_a)
        self.assertEqual(
            self.client.get(detail_url(self.project_a.pk)).status_code,
            status.HTTP_200_OK,
        )

        ProjectMember.objects.filter(
            project=self.project_a, user=self.user_a,
        ).delete()

        self.assertEqual(
            self.client.get(detail_url(self.project_a.pk)).status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_admin_gets_404_for_missing_project(self):
        self.login(self.admin)
        response = self.client.get(detail_url(self.missing_id))

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_non_numeric_id_returns_404_not_500(self):
        """정수가 아닌 pk는 URL 매칭 단계에서 걸러진다 (secure-review 후 lookup_value_regex 적용)."""
        self.login(self.admin)
        response = self.client.get('/api/projects/not-a-number/')

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_member_removal_is_scoped_to_the_project_in_the_url(self):
        """다른 프로젝트의 할당은 지워지지 않는다 (중첩 자원 스코핑)."""
        self.login(self.admin)
        response = self.client.delete(
            member_detail_url(self.project_b.pk, self.user_a.pk),
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)
        self.assertTrue(
            ProjectMember.objects.filter(
                project=self.project_a, user=self.user_a,
            ).exists(),
        )


class RoleControlTests(ProjectTestCase):
    """SEC-003, SEC-004 — 쓰기는 관리자만, 응답은 id에 따라 갈리지 않는다."""

    def test_user_cannot_create_project(self):
        self.login(self.user_a)
        response = self.client.post(LIST_URL, {'name': '새 프로젝트'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(Project.objects.filter(name='새 프로젝트').exists())

    def test_user_cannot_update_assigned_project(self):
        """읽을 수 있어도 수정은 못 한다 (읽기 전용)."""
        self.login(self.user_a)
        response = self.client.patch(
            detail_url(self.project_a.pk), {'name': '변경 시도'}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.project_a.refresh_from_db()
        self.assertEqual(self.project_a.name, '할당된 프로젝트')

    def test_write_response_is_uniform_across_project_ids(self):
        """할당·미할당·없는 id 모두 같은 403 — 응답 차이로 존재를 알아낼 수 없다."""
        self.login(self.user_a)
        payload = {'name': '변경 시도'}
        responses = [
            self.client.patch(detail_url(pk), payload, format='json')
            for pk in (self.project_a.pk, self.project_b.pk, self.missing_id)
        ]

        self.assertEqual(
            [r.status_code for r in responses],
            [status.HTTP_403_FORBIDDEN] * 3,
        )
        self.assertEqual(len({str(r.data) for r in responses}), 1)

    def test_user_cannot_view_members_of_assigned_project(self):
        self.login(self.user_a)
        response = self.client.get(members_url(self.project_a.pk))

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_user_cannot_assign_members(self):
        self.login(self.user_a)
        response = self.client.post(
            members_url(self.project_a.pk), {'user_id': self.user_b.pk}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertFalse(
            ProjectMember.objects.filter(
                project=self.project_a, user=self.user_b,
            ).exists(),
        )

    def test_demoted_admin_is_blocked_immediately(self):
        """역할은 토큰이 아니라 DB의 현재 값으로 판단한다 (SEC-003)."""
        self.login(self.admin)
        self.assertEqual(
            self.client.post(LIST_URL, {'name': '관리자 생성'}, format='json').status_code,
            status.HTTP_201_CREATED,
        )

        self.admin.role = Role.USER
        self.admin.save(update_fields=['role'])

        self.assertEqual(
            self.client.post(LIST_URL, {'name': '강등 후 생성'}, format='json').status_code,
            status.HTTP_403_FORBIDDEN,
        )


class ProjectCrudTests(ProjectTestCase):
    """SFR-004 — 관리자의 등록·수정, 삭제는 비목표."""

    def test_admin_creates_project(self):
        self.login(self.admin)
        response = self.client.post(
            LIST_URL, {'name': '신규', 'description': '설명'}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        project = Project.objects.get(pk=response.data['id'])
        self.assertEqual(project.name, '신규')
        self.assertEqual(project.created_by, self.admin)

    def test_created_by_cannot_be_forged_from_request_body(self):
        """본문의 created_by는 무시되고 인증된 사용자로 저장된다 (SEC-005)."""
        self.login(self.admin)
        response = self.client.post(
            LIST_URL,
            {'name': '위조 시도', 'created_by': self.user_b.pk},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        project = Project.objects.get(pk=response.data['id'])
        self.assertEqual(project.created_by, self.admin)
        self.assertNotEqual(project.created_by, self.user_b)

    def test_admin_updates_project(self):
        self.login(self.admin)
        response = self.client.patch(
            detail_url(self.project_a.pk), {'name': '이름 변경'}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_a.refresh_from_db()
        self.assertEqual(self.project_a.name, '이름 변경')

    def test_project_delete_route_does_not_exist(self):
        """삭제는 비목표 — 라우트 자체를 만들지 않는다 (docs/plan.md §5)."""
        self.login(self.admin)
        response = self.client.delete(detail_url(self.project_a.pk))

        self.assertEqual(response.status_code, status.HTTP_405_METHOD_NOT_ALLOWED)
        self.assertTrue(Project.objects.filter(pk=self.project_a.pk).exists())


class MemberAssignmentTests(ProjectTestCase):
    """SFR-005, QLT-005 — 할당·해제와 데이터 정합성."""

    def test_admin_assigns_user(self):
        self.login(self.admin)
        response = self.client.post(
            members_url(self.project_b.pk), {'user_id': self.user_b.pk}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        membership = ProjectMember.objects.get(
            project=self.project_b, user=self.user_b,
        )
        self.assertEqual(membership.assigned_by, self.admin)

    def test_assignment_grants_access_immediately(self):
        self.login(self.admin)
        self.client.post(
            members_url(self.project_b.pk), {'user_id': self.user_b.pk}, format='json',
        )

        self.login(self.user_b)
        response = self.client.get(detail_url(self.project_b.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_admin_lists_members(self):
        self.login(self.admin)
        response = self.client.get(members_url(self.project_a.pk))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['user']['email'], self.user_a.email)

    def test_duplicate_assignment_is_rejected(self):
        self.login(self.admin)
        response = self.client.post(
            members_url(self.project_a.pk), {'user_id': self.user_a.pk}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(
            ProjectMember.objects.filter(
                project=self.project_a, user=self.user_a,
            ).count(),
            1,
        )

    def test_assigning_unknown_user_is_rejected(self):
        self.login(self.admin)
        response = self.client.post(
            members_url(self.project_a.pk),
            {'user_id': self.user_b.pk + 1000},
            format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(self.project_a.memberships.count(), 1)

    def test_admin_removes_assignment(self):
        self.login(self.admin)
        response = self.client.delete(
            member_detail_url(self.project_a.pk, self.user_a.pk),
        )

        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertFalse(
            ProjectMember.objects.filter(
                project=self.project_a, user=self.user_a,
            ).exists(),
        )

    def test_removing_absent_assignment_returns_404(self):
        self.login(self.admin)
        response = self.client.delete(
            member_detail_url(self.project_a.pk, self.user_b.pk),
        )

        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)


class DataIntegrityTests(ProjectTestCase):
    """DAR-010, QLT-005 — DB 제약이 최종 방어선."""

    def test_unique_constraint_blocks_duplicate_membership(self):
        from django.db import IntegrityError, transaction

        with self.assertRaises(IntegrityError):
            with transaction.atomic():
                ProjectMember.objects.create(
                    project=self.project_a, user=self.user_a, assigned_by=self.admin,
                )

    def test_deleting_project_cascades_to_memberships(self):
        project_id = self.project_a.pk
        self.project_a.delete()

        self.assertFalse(
            ProjectMember.objects.filter(project_id=project_id).exists(),
        )

    def test_creator_cannot_be_deleted_while_referenced(self):
        from django.db.models import ProtectedError

        with self.assertRaises(ProtectedError):
            self.admin.delete()

    def test_assigned_user_cannot_be_deleted_while_assigned(self):
        """할당 기록의 user 쪽도 PROTECT다 (DAR-010, decisions.md)."""
        from django.db.models import ProtectedError

        with self.assertRaises(ProtectedError):
            self.user_a.delete()


class ExcludePathsTests(ProjectTestCase):
    """프로젝트별 분석 제외 경로 — 입력 검증·저장·노출 (RFP 외 자체 개선).

    값이 그대로 Semgrep `--exclude` 인자가 되므로 여기서 걸러진 것만 실행에 도달한다.
    실행 반영은 analysis/tests.py ExcludePathsExecuteTests.
    """

    def _create(self, exclude_paths):
        self.login(self.admin)
        return self.client.post(
            LIST_URL, {'name': '제외 테스트', 'exclude_paths': exclude_paths}, format='json',
        )

    def _patch(self, exclude_paths):
        self.login(self.admin)
        return self.client.patch(
            detail_url(self.project_a.pk), {'exclude_paths': exclude_paths}, format='json',
        )

    def test_defaults_to_empty_list(self):
        self.login(self.admin)
        response = self.client.post(LIST_URL, {'name': '기본'}, format='json')

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['exclude_paths'], [])
        self.assertEqual(Project.objects.get(pk=response.data['id']).exclude_paths, [])

    def test_admin_creates_project_with_exclude_paths(self):
        response = self._create(['catalog/samples', 'tests.py'])

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['exclude_paths'], ['catalog/samples', 'tests.py'])
        project = Project.objects.get(pk=response.data['id'])
        self.assertEqual(project.exclude_paths, ['catalog/samples', 'tests.py'])

    def test_admin_updates_exclude_paths(self):
        response = self._patch(['dogfood'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_a.refresh_from_db()
        self.assertEqual(self.project_a.exclude_paths, ['dogfood'])

    def test_admin_clears_exclude_paths_with_empty_list(self):
        self.project_a.exclude_paths = ['dogfood']
        self.project_a.save()

        response = self._patch([])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.project_a.refresh_from_db()
        self.assertEqual(self.project_a.exclude_paths, [])

    def test_entries_are_normalized_and_deduplicated(self):
        # 앞뒤 공백·슬래시는 Semgrep에 의미가 없으므로 하나의 저장 형태로 맞춘다.
        response = self._patch([' catalog/samples/ ', '/catalog/samples', 'tests.py', 'tests.py'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['exclude_paths'], ['catalog/samples', 'tests.py'])

    def test_glob_and_korean_directory_names_are_accepted(self):
        response = self._patch(['*.min.js', '테스트/픽스처', 'build-?'])

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['exclude_paths'], ['*.min.js', '테스트/픽스처', 'build-?'])

    def test_rejects_unsafe_or_malformed_entries(self):
        # 경로 조작·절대 경로·역슬래시·셸 메타·semgrepignore 부정 등은 인자로 넘기지 않는다.
        for bad in (
            ['../secrets'], ['a/../b'], ['/'], ['C:/Windows'], ['a\\b'], ['a//b'],
            ['-x'], ['!important'], ['a;rm'], ['$(x)'], ['a\nb'], [''], ['   '], ['.'],
            ['x' * 201],
        ):
            with self.subTest(bad=bad):
                response = self._patch(bad)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                # 화면(ApiError.detail)이 읽을 수 있게 평평한 문자열 목록으로 돌려준다.
                self.assertIsInstance(response.data['exclude_paths'], list)
                self.assertIsInstance(str(response.data['exclude_paths'][0]), str)
                self.project_a.refresh_from_db()
                self.assertEqual(self.project_a.exclude_paths, [])

    def test_rejects_non_list_and_non_string_items(self):
        for bad in ('catalog/samples', {'a': 1}, [None], [['x']]):
            with self.subTest(bad=bad):
                response = self._patch(bad)
                self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
                self.assertIn('exclude_paths', response.data)

    def test_rejects_too_many_entries(self):
        response = self._patch([f'dir{i}' for i in range(51)])

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('exclude_paths', response.data)

    def test_error_message_names_the_offending_entry(self):
        response = self._patch(['ok', '../bad'])

        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertIn('2번째', str(response.data['exclude_paths'][0]))
        self.assertIn('../bad', str(response.data['exclude_paths'][0]))

    def test_user_cannot_change_exclude_paths(self):
        # 수정은 관리자 전용 (SEC-003) — 할당된 사용자여도 403.
        self.login(self.user_a)
        response = self.client.patch(
            detail_url(self.project_a.pk), {'exclude_paths': ['x']}, format='json',
        )

        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.project_a.refresh_from_db()
        self.assertEqual(self.project_a.exclude_paths, [])

    def test_assigned_user_sees_exclude_paths_in_detail(self):
        # 결과를 읽는 사람은 무엇이 검사에서 빠졌는지도 알아야 한다.
        self.project_a.exclude_paths = ['catalog/samples']
        self.project_a.save()
        self.login(self.user_a)

        response = self.client.get(detail_url(self.project_a.pk))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['exclude_paths'], ['catalog/samples'])


class ExcludePathMatchingTests(APITestCase):
    """is_excluded가 Semgrep 1.175.0 `--exclude`와 같은 규칙인지 (2026-09-05 실험값)."""

    def test_pattern_with_slash_is_anchored_at_root(self):
        self.assertTrue(is_excluded(('catalog', 'samples', 'v.py'), ['catalog/samples']))
        self.assertTrue(is_excluded(('catalog', 'samples', 'deep', 'v.py'), ['catalog/samples']))
        self.assertFalse(is_excluded(('sub', 'catalog', 'samples', 'v.py'), ['catalog/samples']))
        self.assertFalse(is_excluded(('catalog', 'other.py'), ['catalog/samples']))

    def test_pattern_without_slash_matches_any_depth_name(self):
        self.assertTrue(is_excluded(('tests.py',), ['tests.py']))
        self.assertTrue(is_excluded(('pkg', 'tests.py'), ['tests.py']))
        self.assertTrue(is_excluded(('sub', 'catalog', 'samples', 'v.py'), ['samples']))
        self.assertFalse(is_excluded(('pkg', 'test_x.py'), ['tests.py']))

    def test_glob_patterns(self):
        self.assertTrue(is_excluded(('a', 'b.py'), ['*.py']))
        self.assertTrue(is_excluded(('catalog', 'samples', 'v.py'), ['catalog/sam*']))
        self.assertFalse(is_excluded(('catalog', 'other.py'), ['catalog/sam*']))

    def test_no_patterns_excludes_nothing(self):
        self.assertFalse(is_excluded(('catalog', 'samples', 'v.py'), []))


class ExcludePathsModelValidationTests(ProjectTestCase):
    """모델 validator — Django admin 폼처럼 DRF를 거치지 않는 저장 경로에서도 같은 규칙."""

    def test_full_clean_rejects_invalid_entries(self):
        self.project_a.exclude_paths = ['../etc']
        with self.assertRaises(ValidationError) as ctx:
            self.project_a.full_clean()
        self.assertIn('exclude_paths', ctx.exception.message_dict)

    def test_full_clean_accepts_valid_entries(self):
        self.project_a.exclude_paths = ['catalog/samples', 'tests.py']
        self.project_a.full_clean()  # 예외 없음
