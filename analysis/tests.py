"""분석 실행 파이프라인 시험 (TST-004, SFR-007~009, SEC-005~008).

핵심 두 가지:
1. Zip Slip — 압축 안의 경로가 격리 디렉토리 밖을 가리켜도 파일이 써지지 않는다.
2. IDOR — projects 앱과 같은 원칙으로, URL의 project_id·run id를 조작해도
   할당되지 않은 프로젝트의 분석에는 도달할 수 없다.

Semgrep 실제 실행은 subprocess.run을 모킹해 CI·바이너리 유무와 무관하게 돈다 —
바이너리 자체가 기대대로 동작하는지는 analysis/services.py를 직접 호출하는
수동 스모크 테스트(개발 중 확인 완료)로 별도 검증했다.
"""

import io
import json
import shutil
import stat
import tempfile
import zipfile
from pathlib import Path
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.test import override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import Role
from projects.models import Project, ProjectMember

from .models import AnalysisRun, AnalysisStatus
from .services import source_dir, workspace_dir

User = get_user_model()

PASSWORD = 'sast-test-pw-9182'


def list_url(project_id):
    return reverse('analysis:analysis-run-list', args=[project_id])


def detail_url(run_id):
    return reverse('analysis:analysis-run-detail', args=[run_id])


def execute_url(run_id):
    return reverse('analysis:analysis-run-execute', args=[run_id])


def make_zip(entries=None, infos=None):
    """entries: {파일명: 내용}. infos: [(ZipInfo, 내용)] — external_attr 등 세밀한 조작용."""
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, 'w') as zf:
        for name, content in (entries or {}).items():
            zf.writestr(name, content)
        for info, content in (infos or []):
            zf.writestr(info, content)
    return buf.getvalue()


def upload_file(name='source.zip', **kwargs):
    return SimpleUploadedFile(name, make_zip(**kwargs), content_type='application/zip')


class AnalysisTestCase(APITestCase):
    """관리자 1명, 일반 사용자 2명, project_a(user_a에게 할당)·project_b(미할당).

    격리 디렉토리는 실제 프로젝트의 media/가 아니라 임시 디렉토리로 돌린다 —
    테스트가 실제 작업 영역을 더럽히지 않게.
    """

    def setUp(self):
        super().setUp()
        self.tmp_root = Path(tempfile.mkdtemp(prefix='analysis-tests-'))
        self.addCleanup(shutil.rmtree, self.tmp_root, ignore_errors=True)
        self._settings_override = override_settings(ANALYSIS_WORKSPACE_ROOT=self.tmp_root)
        self._settings_override.enable()
        self.addCleanup(self._settings_override.disable)

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

        self.missing_project_id = Project.objects.order_by('-pk').first().pk + 1000

    def login(self, user):
        self.client.force_authenticate(user=user)


class UnauthenticatedTests(AnalysisTestCase):
    """SEC-002 — 인증 없이는 아무것도 열리지 않는다."""

    def test_list_requires_authentication(self):
        response = self.client.get(list_url(self.project_a.pk))
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)

    def test_upload_requires_authentication(self):
        response = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_401_UNAUTHORIZED)


class UploadTests(AnalysisTestCase):
    """SFR-007, SEC-007 — 업로드·압축 해제·격리."""

    def test_admin_uploads_zip_and_run_is_pending(self):
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={'app.py': 'print(1)\n'})},
            format='multipart',
        )

        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['status'], AnalysisStatus.PENDING)
        run = AnalysisRun.objects.get(pk=response.data['id'])
        self.assertEqual(run.project, self.project_a)
        self.assertEqual(run.created_by, self.admin)

    def test_extracted_files_land_only_in_this_run_workspace(self):
        """실행 1건의 소스는 자신의 격리 디렉토리에만 존재한다 (SEC-007)."""
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={'nested/app.py': 'x = 1\n'})},
            format='multipart',
        )
        run = AnalysisRun.objects.get(pk=response.data['id'])

        extracted = source_dir(run) / 'nested' / 'app.py'
        self.assertTrue(extracted.exists())
        self.assertEqual(extracted.read_text(), 'x = 1\n')

    def test_two_uploads_get_separate_workspaces(self):
        self.login(self.admin)
        r1 = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={'a.py': '1\n'})}, format='multipart',
        )
        r2 = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={'a.py': '2\n'})}, format='multipart',
        )
        run1 = AnalysisRun.objects.get(pk=r1.data['id'])
        run2 = AnalysisRun.objects.get(pk=r2.data['id'])

        self.assertNotEqual(workspace_dir(run1), workspace_dir(run2))
        self.assertEqual((source_dir(run1) / 'a.py').read_text(), '1\n')
        self.assertEqual((source_dir(run2) / 'a.py').read_text(), '2\n')

    def test_non_zip_file_is_rejected(self):
        self.login(self.admin)
        bad_file = SimpleUploadedFile('app.py', b'print(1)', content_type='text/plain')
        response = self.client.post(
            list_url(self.project_a.pk), {'file': bad_file}, format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AnalysisRun.objects.count(), 0)

    def test_corrupt_zip_is_rejected(self):
        self.login(self.admin)
        bad_file = SimpleUploadedFile('bad.zip', b'not-actually-a-zip', content_type='application/zip')
        response = self.client.post(
            list_url(self.project_a.pk), {'file': bad_file}, format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AnalysisRun.objects.count(), 0)


class ZipSlipDefenseTests(AnalysisTestCase):
    """SEC-008 — 시연 핵심. 압축 안 경로가 격리 디렉토리 밖을 가리키면 아무것도 안 써진다."""

    def _assert_upload_rejected(self, zip_bytes):
        self.login(self.admin)
        before = AnalysisRun.objects.count()
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': SimpleUploadedFile('evil.zip', zip_bytes, content_type='application/zip')},
            format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
        self.assertEqual(AnalysisRun.objects.count(), before)
        return response

    def test_parent_directory_traversal_is_rejected(self):
        zip_bytes = make_zip(entries={'../../evil.txt': 'pwned'})
        self._assert_upload_rejected(zip_bytes)

        # 격리 루트 밖에는 아무 흔적도 없어야 한다.
        for path in self.tmp_root.rglob('evil.txt'):
            self.fail(f'격리 루트 밖에 파일이 써졌다: {path}')
        self.assertFalse((self.tmp_root.parent / 'evil.txt').exists())

    def test_absolute_path_entry_is_rejected(self):
        # zipfile은 절대경로 표기를 그대로 저장할 수 있다 (writestr은 이름을 검증하지 않음).
        zip_bytes = make_zip(entries={'/etc/evil.txt': 'pwned'})
        self._assert_upload_rejected(zip_bytes)

    def test_windows_drive_path_entry_is_rejected(self):
        zip_bytes = make_zip(entries={'C:/Windows/evil.txt': 'pwned'})
        self._assert_upload_rejected(zip_bytes)

    def test_symlink_entry_is_rejected(self):
        info = zipfile.ZipInfo('link.py')
        info.external_attr = (stat.S_IFLNK | 0o777) << 16
        zip_bytes = make_zip(infos=[(info, '../../../etc/passwd')])
        self._assert_upload_rejected(zip_bytes)

    def test_valid_zip_alongside_traversal_entry_extracts_nothing(self):
        """정상 파일과 악성 항목이 섞여 있어도 정상 파일조차 부분 추출되지 않는다."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as zf:
            zf.writestr('good.py', 'print(1)\n')
            zf.writestr('../evil.txt', 'pwned')
        response = self._assert_upload_rejected(buf.getvalue())
        self.assertIn('file', response.data)


class ZipLimitTests(AnalysisTestCase):
    """SEC-008 — zip bomb 기본 방어. 상한값은 테스트 안에서 낮춰서 확인한다."""

    def test_too_many_files_is_rejected(self):
        with override_settings(ANALYSIS_MAX_EXTRACTED_FILES=2):
            self.login(self.admin)
            zip_bytes = make_zip(entries={f'f{i}.py': 'x' for i in range(3)})
            response = self.client.post(
                list_url(self.project_a.pk),
                {'file': SimpleUploadedFile('many.zip', zip_bytes, content_type='application/zip')},
                format='multipart',
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(AnalysisRun.objects.count(), 0)

    def test_total_extracted_size_over_limit_is_rejected(self):
        with override_settings(ANALYSIS_MAX_EXTRACTED_SIZE=10):
            self.login(self.admin)
            zip_bytes = make_zip(entries={'big.py': 'x' * 1000})
            response = self.client.post(
                list_url(self.project_a.pk),
                {'file': SimpleUploadedFile('big.zip', zip_bytes, content_type='application/zip')},
                format='multipart',
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(AnalysisRun.objects.count(), 0)

    def test_upload_over_raw_size_limit_is_rejected(self):
        with override_settings(ANALYSIS_MAX_UPLOAD_SIZE=10):
            self.login(self.admin)
            response = self.client.post(
                list_url(self.project_a.pk),
                {'file': upload_file(entries={'a.py': 'x' * 100})},
                format='multipart',
            )
            self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)
            self.assertEqual(AnalysisRun.objects.count(), 0)


class IdorDefenseTests(AnalysisTestCase):
    """SEC-005, SEC-006 — projects 앱과 같은 원칙을 analysis에도 적용."""

    def test_user_cannot_list_runs_of_unassigned_project(self):
        self.login(self.user_a)
        response = self.client.get(list_url(self.project_b.pk))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_unassigned_and_missing_project_are_indistinguishable(self):
        self.login(self.user_a)
        unassigned = self.client.get(list_url(self.project_b.pk))
        missing = self.client.get(list_url(self.missing_project_id))
        self.assertEqual(unassigned.status_code, missing.status_code)
        self.assertEqual(unassigned.data, missing.data)

    def test_user_can_list_runs_of_assigned_project(self):
        self.login(self.admin)
        self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )

        self.login(self.user_a)
        response = self.client.get(list_url(self.project_a.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 1)

    def test_user_cannot_retrieve_run_of_unassigned_project(self):
        self.login(self.admin)
        created = self.client.post(
            list_url(self.project_b.pk), {'file': upload_file()}, format='multipart',
        )

        self.login(self.user_a)
        response = self.client.get(detail_url(created.data['id']))
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_user_cannot_execute_run_of_unassigned_project(self):
        """실행은 쓰기 작업이라 IsAdminRole이 조회보다 먼저 걸린다 — 일반 사용자는
        할당 여부와 무관하게 균일 403 (projects 앱의 SEC-006 응답 정책과 동일).
        """
        self.login(self.admin)
        created = self.client.post(
            list_url(self.project_b.pk), {'file': upload_file()}, format='multipart',
        )

        self.login(self.user_a)
        response = self.client.post(execute_url(created.data['id']))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_admin_gets_404_for_missing_run(self):
        self.login(self.admin)
        missing_run_id = 999999
        self.assertEqual(
            self.client.get(detail_url(missing_run_id)).status_code,
            status.HTTP_404_NOT_FOUND,
        )

    def test_revoking_assignment_blocks_run_access_immediately(self):
        self.login(self.admin)
        created = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )

        self.login(self.user_a)
        self.assertEqual(
            self.client.get(detail_url(created.data['id'])).status_code,
            status.HTTP_200_OK,
        )

        ProjectMember.objects.filter(project=self.project_a, user=self.user_a).delete()

        self.assertEqual(
            self.client.get(detail_url(created.data['id'])).status_code,
            status.HTTP_404_NOT_FOUND,
        )


class RoleControlTests(AnalysisTestCase):
    """SEC-003, SEC-004 — 업로드·실행은 관리자만, 조회는 스코프된 인증 사용자."""

    def test_user_cannot_upload(self):
        self.login(self.user_a)
        response = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)
        self.assertEqual(AnalysisRun.objects.count(), 0)

    def test_user_cannot_execute(self):
        self.login(self.admin)
        created = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )

        self.login(self.user_a)
        response = self.client.post(execute_url(created.data['id']))
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)

    def test_demoted_admin_is_blocked_immediately(self):
        self.login(self.admin)
        self.assertEqual(
            self.client.post(
                list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
            ).status_code,
            status.HTTP_201_CREATED,
        )

        self.admin.role = Role.USER
        self.admin.save(update_fields=['role'])

        response = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file()}, format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_403_FORBIDDEN)


class ExecuteStatusTests(AnalysisTestCase):
    """SFR-008~009, SFR-015 — 상태 전이. Semgrep 호출은 모킹한다."""

    def _upload(self, entries=None):
        if entries is None:
            entries = {'app.py': 'eval(input())\n'}
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries=entries)},
            format='multipart',
        )
        return response.data['id']

    @patch('analysis.services.subprocess.run')
    def test_successful_execution_stores_raw_result(self, mock_run):
        run_id = self._upload()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [{'check_id': 'x'}], 'errors': []})
        mock_run.return_value.stderr = ''

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertEqual(len(run.raw_result['results']), 1)
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)

    @patch('analysis.services.subprocess.run')
    def test_nonzero_exit_marks_failed(self, mock_run):
        run_id = self._upload()
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ''
        mock_run.return_value.stderr = 'semgrep: config error'

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertIn('config error', run.error_message)

    @patch('analysis.services.subprocess.run')
    def test_timeout_marks_failed(self, mock_run):
        import subprocess
        run_id = self._upload()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='semgrep', timeout=120)

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        self.assertIn('초과', AnalysisRun.objects.get(pk=run_id).error_message)

    @patch('analysis.services.subprocess.run')
    def test_running_or_succeeded_run_cannot_be_re_executed(self, mock_run):
        run_id = self._upload()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
        mock_run.return_value.stderr = ''

        first = self.client.post(execute_url(run_id))
        self.assertEqual(first.status_code, status.HTTP_200_OK)

        second = self.client.post(execute_url(run_id))
        self.assertEqual(second.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(mock_run.call_count, 1)

    @patch('analysis.services.subprocess.run')
    def test_empty_zip_marks_failed_without_running_semgrep(self, mock_run):
        # 빈 zip은 업로드 자체는 성공하지만, 실행 시점에 분석 대상이 없어
        # Semgrep 호출 없이 FAILED가 되어야 한다 (TST-008).
        run_id = self._upload(entries={})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertIn('분석 가능한 소스 파일이 없습니다', run.error_message)
        self.assertIsNotNone(run.finished_at)
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_zip_without_supported_files_marks_failed_without_running_semgrep(self, mock_run):
        run_id = self._upload(entries={'readme.md': '# docs only\n'})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        self.assertIn(
            '분석 가능한 소스 파일이 없습니다',
            AnalysisRun.objects.get(pk=run_id).error_message,
        )
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_failed_run_can_be_retried(self, mock_run):
        run_id = self._upload()
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ''
        mock_run.return_value.stderr = 'boom'
        self.client.post(execute_url(run_id))

        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
        mock_run.return_value.stderr = ''
        retry = self.client.post(execute_url(run_id))

        self.assertEqual(retry.status_code, status.HTTP_200_OK)
        self.assertEqual(retry.data['status'], AnalysisStatus.SUCCEEDED)


class AccessLogTests(AnalysisTestCase):
    """결과 열람 접근 로그 (RFP 외 자체 개선, docs/decisions.md 2026-09-01)."""

    def _make_run(self, project):
        return AnalysisRun.objects.create(
            project=project, created_by=self.admin, original_filename='src.zip',
        )

    def test_run_detail_view_is_logged(self):
        run = self._make_run(self.project_a)
        self.login(self.user_a)
        with self.assertLogs('access', level='INFO') as captured:
            res = self.client.get(detail_url(run.pk))
        self.assertEqual(res.status_code, status.HTTP_200_OK)
        line = captured.output[0]
        self.assertIn('user=a@example.com', line)
        self.assertIn('action=run_detail', line)
        self.assertIn(f'run={run.pk}', line)
        self.assertIn(f'project={self.project_a.pk}', line)

    def test_denied_view_is_not_logged(self):
        """스코프 밖 404는 열람이 아니다 — 기록을 남기지 않는다."""
        run = self._make_run(self.project_b)
        self.login(self.user_a)
        with self.assertNoLogs('access', level='INFO'):
            res = self.client.get(detail_url(run.pk))
        self.assertEqual(res.status_code, status.HTTP_404_NOT_FOUND)
