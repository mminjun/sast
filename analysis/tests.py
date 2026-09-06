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
import os
import shutil
import stat
import subprocess
import tempfile
import textwrap
import zipfile
from datetime import timedelta
from pathlib import Path
from unittest import skipUnless
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.files.uploadedfile import SimpleUploadedFile
from django.core.management import call_command
from django.tasks import default_task_backend
from django.test import SimpleTestCase, override_settings, tag
from django.urls import reverse
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APITestCase, APITransactionTestCase

from accounts.models import Role
from projects.models import Project, ProjectMember

from .models import AnalysisRun, AnalysisStatus
from .services import (
    DATAFLOW_TRACE_FILE, STALE_RUN_MESSAGE, execute_analysis, fs_path, mark_queued, reap_stale_runs,
    source_dir, start_run,
    workspace_dir,
)
from .taint import analyze_directory, analyze_source
from .taint.python_analyzer import LOOP_PASSES, SUMMARY_PASSES
from .tasks import run_analysis

User = get_user_model()

PASSWORD = 'sast-test-pw-9182'

# 실제 Semgrep을 돌리는 시험은 바이너리가 있을 때만 (catalog/tests.py와 같은 방식).
SEMGREP_AVAILABLE = shutil.which('semgrep') is not None


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

    def test_macos_metadata_entries_are_skipped(self):
        """Finder 압축의 __MACOSX/·._*·.DS_Store는 소스가 아니므로 풀지 않는다.

        .py를 흉내 낸 AppleDouble 파일을 Semgrep이 파싱하려다 NUL이 든 오류를 내고,
        그 JSON이 jsonb에 저장되지 못해 실행이 RUNNING에 고착됐던 사례(2026-09-04).
        """
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={
                'app/main.py': 'x = 1',
                '__MACOSX/app/._main.py': 'Mac OS X binary',
                'app/._helper.py': 'Mac OS X binary',
                '.DS_Store': 'binary',
                'app/.DS_Store': 'binary',
            })},
            format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        run = AnalysisRun.objects.get(pk=response.data['id'])
        extracted = sorted(
            p.relative_to(source_dir(run)).as_posix()
            for p in source_dir(run).rglob('*') if p.is_file()
        )
        self.assertEqual(extracted, ['app/main.py'])

    def test_entry_beyond_windows_max_path_is_extracted(self):
        """격리 루트까지 합쳐 260자를 넘는 항목도 풀린다.

        깊은 Java 패키지 경로가 든 zip이 Windows MAX_PATH에 걸려 FileNotFoundError로
        500이 났던 사례(2026-09-04, 261자). 확장 경로(fs_path)로 쓰므로 길이 제한이 없다.
        """
        deep_name = '/'.join(['d' * 50] * 5) + '/' + 'f' * 40 + '.py'
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={deep_name: 'x = 1'})},
            format='multipart',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        run = AnalysisRun.objects.get(pk=response.data['id'])
        target = source_dir(run) / deep_name
        self.assertGreater(len(str(target)), 260)
        with open(fs_path(target), encoding='utf-8') as handle:
            self.assertEqual(handle.read(), 'x = 1')

    @patch('analysis.serializers.extract_zip_safely', side_effect=OSError('disk'))
    def test_unexpected_extract_failure_leaves_no_run_or_workspace(self, _mock):
        """검증 밖의 추출 실패는 500이어도 PENDING 행·반쯤 풀린 디렉토리를 남기지 않는다."""
        self.login(self.admin)
        with self.assertRaises(OSError):
            self.client.post(
                list_url(self.project_a.pk),
                {'file': upload_file(entries={'app/main.py': 'x = 1'})},
                format='multipart',
            )
        self.assertEqual(AnalysisRun.objects.count(), 0)
        self.assertEqual(list(self.tmp_root.iterdir()), [])

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

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
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

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertIn('config error', run.error_message)

    @patch('analysis.services.subprocess.run')
    def test_timeout_marks_failed(self, mock_run):
        import subprocess
        run_id = self._upload()
        mock_run.side_effect = subprocess.TimeoutExpired(cmd='semgrep', timeout=120)

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        self.assertIn('초과', AnalysisRun.objects.get(pk=run_id).error_message)

    @patch('analysis.services.subprocess.run')
    def test_running_or_succeeded_run_cannot_be_re_executed(self, mock_run):
        run_id = self._upload()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
        mock_run.return_value.stderr = ''

        first = self.client.post(execute_url(run_id))
        self.assertEqual(first.status_code, status.HTTP_202_ACCEPTED)

        second = self.client.post(execute_url(run_id))
        self.assertEqual(second.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(mock_run.call_count, 1)

    @patch('analysis.services.subprocess.run')
    def test_nul_in_semgrep_output_is_stripped_before_save(self, mock_run):
        """PostgreSQL jsonb는 U+0000을 저장하지 못한다 — 도구 출력의 NUL은 걷어낸다."""
        run_id = self._upload()
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({
            'results': [],
            'errors': [{'message': 'parse error: `' + chr(0) + chr(0) + '` at 1:1'}],
        })
        mock_run.return_value.stderr = ''

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertEqual(run.raw_result['errors'][0]['message'], 'parse error: `` at 1:1')

    @patch('analysis.services.subprocess.run')
    def test_empty_zip_marks_failed_without_running_semgrep(self, mock_run):
        # 빈 zip은 업로드 자체는 성공하지만, 실행 시점에 분석 대상이 없어
        # Semgrep 호출 없이 FAILED가 되어야 한다 (TST-008).
        run_id = self._upload(entries={})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertIn('분석 가능한 소스 파일이 없습니다', run.error_message)
        self.assertIsNotNone(run.finished_at)
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_zip_with_only_java_or_js_sources_is_scanned(self, mock_run):
        """Java·JS 룰이 붙은 뒤로 .java/.js/.jsx/.ts/.tsx만 든 zip도 분석 대상 (SFR-011)."""
        for entries in ({'App.java': 'class App {}\n'}, {'app.jsx': 'export default 1;\n'},
                        {'app.ts': 'const a: number = 1;\n'}):
            mock_run.reset_mock()
            run_id = self._upload(entries=entries)
            mock_run.return_value.returncode = 0
            mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
            mock_run.return_value.stderr = ''

            response = self.client.post(execute_url(run_id))

            self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED, entries)
            mock_run.assert_called_once()

    @patch('analysis.services.subprocess.run')
    def test_zip_with_only_c_sources_is_scanned(self, mock_run):
        """C 룰이 붙은 뒤로 .c/.h만 든 zip도 분석 대상이다 (SFR-011, TST-008)."""
        run_id = self._upload(entries={'main.c': 'int main(void) { return 0; }\n',
                                       'util.h': '#define X 1\n'})
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
        mock_run.return_value.stderr = ''

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        mock_run.assert_called_once()

    @patch('analysis.services.subprocess.run')
    def test_zip_without_supported_files_marks_failed_without_running_semgrep(self, mock_run):
        run_id = self._upload(entries={'readme.md': '# docs only\n'})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
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

        self.assertEqual(retry.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(retry.data['status'], AnalysisStatus.SUCCEEDED)


class ExcludePathsExecuteTests(AnalysisTestCase):
    """프로젝트별 분석 제외 경로가 실행에 반영되는가 (RFP 외 자체 개선).

    Semgrep 인자 전달은 모킹으로, 실제 제외 동작은 바이너리가 있을 때 한 번 실증한다.
    """

    def _upload(self, entries):
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries=entries)},
            format='multipart',
        )
        return response.data['id']

    def _succeed(self, mock_run):
        mock_run.return_value.returncode = 0
        mock_run.return_value.stdout = json.dumps({'results': [], 'errors': []})
        mock_run.return_value.stderr = ''

    def _semgrep_args(self, mock_run):
        return mock_run.call_args.args[0]

    @patch('analysis.services.subprocess.run')
    def test_exclude_paths_become_semgrep_exclude_arguments(self, mock_run):
        self.project_a.exclude_paths = ['catalog/samples', 'tests.py']
        self.project_a.save()
        run_id = self._upload({'app.py': 'eval(input())\n', 'catalog/samples/v.py': 'x = 1\n'})
        self._succeed(mock_run)

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        args = self._semgrep_args(mock_run)
        self.assertIn('--exclude=catalog/samples', args)
        self.assertIn('--exclude=tests.py', args)
        # 대상 경로는 마지막 인자 — 제외 옵션이 대상 뒤에 붙어 무시되지 않는다.
        self.assertLess(args.index('--exclude=tests.py'), len(args) - 1)
        # 프로젝트 루트를 소스 디렉토리로 고정해야 `/`가 든 패턴이 zip 루트에 앵커된다 —
        # 없으면 Semgrep이 위로 .git을 찾아 우리 저장소를 루트로 삼는다 (run 51 사고).
        run = AnalysisRun.objects.get(pk=run_id)
        self.assertIn(f'--project-root={os.path.abspath(source_dir(run))}', args)
        # taint 오염 경로는 텍스트 출력에만 있다 — 작업 영역에 같이 받아 둔다 (catalog/taint_trace.py).
        self.assertIn('--dataflow-traces', args)
        self.assertIn(
            f'--text-output={os.path.abspath(workspace_dir(run) / DATAFLOW_TRACE_FILE)}', args,
        )
        self.assertEqual(args[args.index('--max-lines-per-finding') + 1], '0')

    @patch('analysis.services.subprocess.run')
    def test_empty_exclude_paths_adds_no_exclude_argument(self, mock_run):
        self.assertEqual(self.project_a.exclude_paths, [])
        run_id = self._upload({'app.py': 'eval(input())\n'})
        self._succeed(mock_run)

        self.client.post(execute_url(run_id))

        self.assertFalse(any(a.startswith('--exclude') for a in self._semgrep_args(mock_run)))

    @patch('analysis.services.subprocess.run')
    def test_exclude_paths_are_read_at_execution_time(self, mock_run):
        # 업로드 뒤에 제외 경로를 바꿔도 실행에 반영된다 — 실행 시점 설정을 읽는다.
        run_id = self._upload({'app.py': 'eval(input())\n'})
        self.project_a.exclude_paths = ['vendor']
        self.project_a.save()
        self._succeed(mock_run)

        self.client.post(execute_url(run_id))

        self.assertIn('--exclude=vendor', self._semgrep_args(mock_run))

    @patch('analysis.services.subprocess.run')
    def test_everything_excluded_marks_failed_without_running_semgrep(self, mock_run):
        # 제외 후 대상이 0개면 빈 zip과 같은 함정(exit 0·0건 SUCCEEDED)이라 실패로 기록하되,
        # 원인이 zip이 아니라 제외 설정임을 메시지로 알린다.
        self.project_a.exclude_paths = ['samples', 'tests.py']
        self.project_a.save()
        run_id = self._upload({'samples/v.py': 'x\n', 'pkg/tests.py': 'y\n', 'README.md': '#\n'})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        message = AnalysisRun.objects.get(pk=run_id).error_message
        self.assertIn('제외 경로를 적용하면', message)
        self.assertIn('samples', message)
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_zip_without_sources_keeps_original_message_even_with_excludes(self, mock_run):
        # 제외와 무관하게 애초에 대상이 없으면 기존 메시지 — 제외 탓으로 오도하지 않는다.
        self.project_a.exclude_paths = ['samples']
        self.project_a.save()
        run_id = self._upload({'README.md': '#\n'})

        self.client.post(execute_url(run_id))

        self.assertIn(
            '분석 가능한 소스 파일이 없습니다',
            AnalysisRun.objects.get(pk=run_id).error_message,
        )
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_anchored_pattern_does_not_exclude_nested_same_named_directory(self, mock_run):
        # `/`가 든 패턴은 루트 기준 — sub/catalog/samples는 남아 스캔된다 (Semgrep과 같은 규칙).
        self.project_a.exclude_paths = ['catalog/samples']
        self.project_a.save()
        run_id = self._upload({'sub/catalog/samples/v.py': 'x\n'})
        self._succeed(mock_run)

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        mock_run.assert_called_once()

    @patch('analysis.services.subprocess.run')
    def test_invalid_stored_exclude_paths_fail_the_run_before_semgrep(self, mock_run):
        # 심층 방어 — API 검증을 거치지 않고(admin·shell) 저장된 값도 인자가 되기 전에 다시
        # 검증한다. 잘못된 값이면 실행을 실패로 기록하고 Semgrep을 부르지 않는다.
        Project.objects.filter(pk=self.project_a.pk).update(exclude_paths=['../etc'])
        run_id = self._upload({'app.py': 'eval(input())\n'})

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.data['status'], AnalysisStatus.FAILED)
        self.assertIn('제외 경로가 올바르지 않습니다', AnalysisRun.objects.get(pk=run_id).error_message)
        mock_run.assert_not_called()

    @tag('semgrep')  # 실제 Semgrep 실행 — 평소엔 --exclude-tag=semgrep으로 건너뛴다 (CLAUDE.md)
    @skipUnless(SEMGREP_AVAILABLE, 'semgrep 바이너리가 없어 실제 제외 동작은 건너뛴다')
    def test_real_semgrep_skips_excluded_files_even_inside_a_git_repo(self):
        # 실제 Semgrep 실행: 제외된 디렉토리의 취약 코드는 결과에 나오지 않는다.
        # 작업 영역을 git 저장소 안에 둔다 — 실서버(media/가 이 저장소 아래)와 같은 조건.
        # --project-root 없이는 Semgrep이 위의 .git을 루트로 삼아 `/`가 든 패턴이 저장소
        # 기준으로 앵커되고 제외가 통째로 무시됐다 (2026-09-06 run 51: 229건 그대로).
        subprocess.run(['git', 'init', '-q', str(self.tmp_root)], check=True, capture_output=True)
        self.project_a.exclude_paths = ['catalog/samples', 'tests.py']
        self.project_a.save()
        vulnerable = 'import subprocess\nsubprocess.call(input(), shell=True)\n'
        run_id = self._upload({
            'app.py': vulnerable,
            'catalog/samples/v.py': vulnerable,
            'pkg/tests.py': vulnerable,
        })

        response = self.client.post(execute_url(run_id))

        self.assertEqual(response.data['status'], AnalysisStatus.SUCCEEDED)
        paths = {
            r['path'].replace('\\', '/') for r in AnalysisRun.objects.get(pk=run_id).raw_result['results']
        }
        self.assertTrue(paths, '취약 코드가 있는 app.py에서 결과가 나와야 한다')
        self.assertTrue(all(p.endswith('/app.py') for p in paths), paths)
        self.assertFalse(any('/samples/' in p or p.endswith('/tests.py') for p in paths), paths)

    def test_semgrepignore_inside_zip_is_not_extracted(self):
        # 업로드 안 .semgrepignore는 Semgrep이 루트에서 읽어 파일을 조용히 빼므로 추출하지
        # 않는다 — 검사에서 빠지는 경로는 프로젝트의 분석 제외 경로 한 곳에서만 정한다.
        run_id = self._upload({
            'app.py': 'x = 1\n',
            '.semgrepignore': 'app.py\n',
            'sub/.semgrepignore': 'app.py\n',
        })

        root = source_dir(AnalysisRun.objects.get(pk=run_id))
        self.assertTrue((root / 'app.py').exists())
        self.assertFalse((root / '.semgrepignore').exists())
        self.assertFalse((root / 'sub' / '.semgrepignore').exists())


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


class RunOrderingAndSequenceTests(AnalysisTestCase):
    """목록 정렬의 결정성과 프로젝트 내 회차 표시 (RFP 외 자체 개선)."""

    def _make_run(self, project):
        return AnalysisRun.objects.create(
            project=project, created_by=self.admin, original_filename='src.zip',
        )

    def test_list_is_ordered_newest_first_with_id_tiebreak(self):
        """같은 시각에 생성돼도 요청마다 순서가 바뀌지 않는다 — (-created_at, -id)."""
        first = self._make_run(self.project_a)
        second = self._make_run(self.project_a)
        third = self._make_run(self.project_a)
        # 같은 분(초)에 생성된 상황을 재현 — created_at을 동일 값으로 맞춘다.
        AnalysisRun.objects.filter(project=self.project_a).update(
            created_at=first.created_at,
        )

        self.login(self.admin)
        ids = [row['id'] for row in self.client.get(list_url(self.project_a.pk)).data]
        self.assertEqual(ids, [third.pk, second.pk, first.pk])

    def test_sequence_is_per_project_creation_order(self):
        """회차는 DB 전체 id가 아니라 프로젝트 안에서의 생성 순번이다."""
        self._make_run(self.project_b)  # 다른 프로젝트 실행이 회차에 끼어들면 안 된다
        first = self._make_run(self.project_a)
        second = self._make_run(self.project_a)

        self.login(self.admin)
        rows = self.client.get(list_url(self.project_a.pk)).data
        sequences = {row['id']: row['sequence'] for row in rows}
        self.assertEqual(sequences, {first.pk: 1, second.pk: 2})

    def test_detail_reports_same_sequence_as_list(self):
        """목록(자리 계산)과 단건(쿼리 폴백)의 회차가 갈라지면 안 된다."""
        self._make_run(self.project_a)
        second = self._make_run(self.project_a)

        self.login(self.admin)
        detail = self.client.get(detail_url(second.pk)).data
        self.assertEqual(detail['sequence'], 2)

    def test_response_includes_project_name(self):
        """브레드크럼 표시용 — id(#22)만으로는 어디로 가는 링크인지 모호하다."""
        run = self._make_run(self.project_a)
        self.login(self.admin)

        detail = self.client.get(detail_url(run.pk)).data
        self.assertEqual(detail['project_name'], self.project_a.name)
        rows = self.client.get(list_url(self.project_a.pk)).data
        self.assertEqual(rows[0]['project_name'], self.project_a.name)


# ---------------------------------------------------------------------------
# 백그라운드 큐 (SFR-008~009, SFR-015, SEC-009 — docs/decisions.md 2026-09-06)
# ---------------------------------------------------------------------------

DUMMY_TASKS = {'default': {'BACKEND': 'django.tasks.backends.dummy.DummyBackend', 'QUEUES': ['default']}}
DATABASE_TASKS = {'default': {'BACKEND': 'django_tasks_db.DatabaseBackend', 'QUEUES': ['default']}}


def _succeeding_semgrep(mock_run, results=None):
    mock_run.return_value.returncode = 0
    mock_run.return_value.stdout = json.dumps({'results': results or [], 'errors': []})
    mock_run.return_value.stderr = ''


@override_settings(TASKS=DUMMY_TASKS)
class QueueEnqueueTests(AnalysisTestCase):
    """실행 요청은 큐에 등록만 하고 즉시 응답한다. DummyBackend는 작업을 실행하지 않고 보관만
    하므로 "등록됐는가"를 정확히 볼 수 있다(테스트 기본인 immediate는 등록 즉시 실행)."""

    def setUp(self):
        super().setUp()
        default_task_backend.clear()
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries={'app.py': 'eval(input())\n'})},
            format='multipart',
        )
        self.run_id = response.data['id']

    @patch('analysis.services.subprocess.run')
    def test_execute_enqueues_and_returns_queued(self, mock_run):
        response = self.client.post(execute_url(self.run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.QUEUED)
        self.assertIsNotNone(response.data['queued_at'])
        self.assertIsNone(response.data['started_at'])
        queued = default_task_backend.results
        self.assertEqual(len(queued), 1)
        self.assertEqual(list(queued[0].args), [self.run_id])
        self.assertEqual(queued[0].task.module_path, 'analysis.tasks.run_analysis')
        mock_run.assert_not_called()  # 실행은 워커의 몫 — 요청 안에서 Semgrep을 돌리지 않는다

    def test_second_execute_while_queued_is_rejected_and_not_enqueued_twice(self):
        first = self.client.post(execute_url(self.run_id))
        second = self.client.post(execute_url(self.run_id))

        self.assertEqual(first.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(second.status_code, status.HTTP_409_CONFLICT)
        self.assertEqual(len(default_task_backend.results), 1)

    def test_failed_run_can_be_requeued_and_old_failure_is_cleared(self):
        # 재실행 시 이전 실패의 사유·시각이 남으면 완료된 run의 응답에 옛 실패 사유가 실린다
        # (2026-09-06 실증에서 발견 — 고착 정리 뒤 재실행이 완료됐는데 error_message가 그대로).
        AnalysisRun.objects.filter(pk=self.run_id).update(
            status=AnalysisStatus.FAILED, error_message='이전 실패',
            started_at=timezone.now(), finished_at=timezone.now(),
        )

        response = self.client.post(execute_url(self.run_id))

        self.assertEqual(response.status_code, status.HTTP_202_ACCEPTED)
        self.assertEqual(response.data['status'], AnalysisStatus.QUEUED)
        self.assertEqual(response.data['error_message'], '')
        self.assertIsNone(response.data['started_at'])
        self.assertIsNone(response.data['finished_at'])

    def test_enqueue_failure_reverts_run_to_pending(self):
        # 큐 등록(INSERT)이 실패하면 "작업 없는 QUEUED"가 남아 복구 경로가 사라진다 —
        # PENDING으로 되돌려 실행 버튼이 다시 보이게 한다.
        with patch('analysis.views.run_analysis') as mocked_task:
            mocked_task.enqueue.side_effect = RuntimeError('queue down')
            with self.assertRaises(RuntimeError):
                self.client.post(execute_url(self.run_id))

        run = AnalysisRun.objects.get(pk=self.run_id)
        self.assertEqual(run.status, AnalysisStatus.PENDING)
        self.assertIsNone(run.queued_at)


class RunAnalysisTaskTests(AnalysisTestCase):
    """워커가 실행하는 작업 함수 자체. 큐 백엔드와 무관하게 직접 호출한다."""

    def _queued_run(self, entries=None):
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk),
            {'file': upload_file(entries=entries or {'app.py': 'eval(input())\n'})},
            format='multipart',
        )
        run = AnalysisRun.objects.get(pk=response.data['id'])
        self.assertTrue(mark_queued(run))
        return run

    @patch('analysis.services.subprocess.run')
    def test_task_runs_queued_run_to_completion(self, mock_run):
        run = self._queued_run()
        _succeeding_semgrep(mock_run, results=[{'check_id': 'x'}])

        run_analysis.call(run.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertIsNotNone(run.started_at)
        self.assertIsNotNone(run.finished_at)
        self.assertEqual(run.raw_result['results'], [{'check_id': 'x'}])
        mock_run.assert_called_once()

    @patch('analysis.services.subprocess.run')
    def test_duplicate_delivery_does_not_run_semgrep_again(self, mock_run):
        # 큐는 최소 한 번 전달이다 — 같은 작업이 두 번 오면 두 번째는 QUEUED→RUNNING 조건부
        # UPDATE가 0행이라 아무것도 하지 않는다 (services.start_run).
        run = self._queued_run()
        _succeeding_semgrep(mock_run)
        run_analysis.call(run.pk)
        finished_at = AnalysisRun.objects.get(pk=run.pk).finished_at

        run_analysis.call(run.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertEqual(run.finished_at, finished_at)
        self.assertEqual(mock_run.call_count, 1)

    @patch('analysis.services.subprocess.run')
    def test_task_on_run_that_is_not_queued_is_a_no_op(self, mock_run):
        run = self._queued_run()
        AnalysisRun.objects.filter(pk=run.pk).update(status=AnalysisStatus.PENDING)

        run_analysis.call(run.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.PENDING)
        mock_run.assert_not_called()

    @patch('analysis.services.subprocess.run')
    def test_task_for_deleted_run_is_ignored(self, mock_run):
        run_analysis.call(self.missing_project_id)  # 존재하지 않는 pk — 예외 없이 끝난다
        mock_run.assert_not_called()

    def test_unexpected_exception_marks_failed_and_reraises(self):
        # run_semgrep이 스스로 처리하지 못한 예외는 RUNNING 고착 대신 FAILED로 남기고,
        # 큐 쪽 작업 행에도 traceback이 기록되도록 다시 올린다.
        run = self._queued_run()
        with patch('analysis.services.run_semgrep', side_effect=RuntimeError('disk gone')):
            with self.assertRaises(RuntimeError):
                run_analysis.call(run.pk)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.FAILED)
        self.assertIn('RuntimeError', run.error_message)
        self.assertIn('disk gone', run.error_message)
        self.assertIsNotNone(run.finished_at)


class StaleRunReapTests(AnalysisTestCase):
    """워커가 작업 중 죽어 RUNNING에 남은 실행 정리 (services.reap_stale_runs)."""

    def _run(self, status_value, started_ago=None, queued_ago=None):
        now = timezone.now()
        return AnalysisRun.objects.create(
            project=self.project_a, created_by=self.admin, original_filename='x.zip',
            status=status_value,
            started_at=now - started_ago if started_ago else None,
            queued_at=now - queued_ago if queued_ago else None,
        )

    def _beyond_threshold(self):
        return timedelta(
            seconds=settings.ANALYSIS_SEMGREP_TIMEOUT + settings.ANALYSIS_STALE_RUN_GRACE + 60
        )

    def test_reaps_running_older_than_timeout_plus_grace(self):
        stale = self._run(AnalysisStatus.RUNNING, started_ago=self._beyond_threshold())

        self.assertEqual(reap_stale_runs(), 1)

        stale.refresh_from_db()
        self.assertEqual(stale.status, AnalysisStatus.FAILED)
        self.assertEqual(stale.error_message, STALE_RUN_MESSAGE)
        self.assertIsNotNone(stale.finished_at)

    def test_keeps_recent_running_and_long_queued(self):
        # 최근 RUNNING은 정상 실행 중일 수 있고, QUEUED는 워커 1개에 밀린 정상 대기일 수 있다.
        recent = self._run(AnalysisStatus.RUNNING, started_ago=timedelta(seconds=10))
        waiting = self._run(AnalysisStatus.QUEUED, queued_ago=self._beyond_threshold())

        self.assertEqual(reap_stale_runs(), 0)

        recent.refresh_from_db()
        waiting.refresh_from_db()
        self.assertEqual(recent.status, AnalysisStatus.RUNNING)
        self.assertEqual(waiting.status, AnalysisStatus.QUEUED)

    def test_reap_is_idempotent(self):
        self._run(AnalysisStatus.RUNNING, started_ago=self._beyond_threshold())
        reap_stale_runs()
        self.assertEqual(reap_stale_runs(), 0)


@override_settings(TASKS=DATABASE_TASKS)
class WorkerCommandTests(APITransactionTestCase):
    """실제 DB 큐 백엔드로 한 바퀴 — 등록된 작업을 analysis_worker가 집어 가고, 시작 시 고착된
    실행을 먼저 정리한다. 워커 루프가 연결 정리(close_old_connections)를 하므로 TestCase의
    트랜잭션 안에서는 돌 수 없어 TransactionTestCase를 쓴다."""

    def setUp(self):
        super().setUp()
        tmp_root = Path(tempfile.mkdtemp(prefix='analysis-worker-tests-'))
        self.addCleanup(shutil.rmtree, tmp_root, ignore_errors=True)
        overridden = override_settings(ANALYSIS_WORKSPACE_ROOT=tmp_root)
        overridden.enable()
        self.addCleanup(overridden.disable)
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.project = Project.objects.create(name='p', created_by=self.admin)
        self.client.force_authenticate(user=self.admin)

    def _upload(self):
        response = self.client.post(
            list_url(self.project.pk),
            {'file': upload_file(entries={'app.py': 'eval(input())\n'})},
            format='multipart',
        )
        return AnalysisRun.objects.get(pk=response.data['id'])

    @patch('analysis.services.subprocess.run')
    def test_worker_reaps_stale_run_then_processes_queued_work(self, mock_run):
        stale = AnalysisRun.objects.create(
            project=self.project, created_by=self.admin, original_filename='old.zip',
            status=AnalysisStatus.RUNNING,
            started_at=timezone.now() - timedelta(days=1),
        )
        run = self._upload()
        _succeeding_semgrep(mock_run)

        response = self.client.post(execute_url(run.pk))
        self.assertEqual(response.data['status'], AnalysisStatus.QUEUED)  # 워커 전이라 대기열

        call_command(
            'analysis_worker', '--batch', '--no-startup-delay', '--no-reload', '--interval', '0.1',
        )

        run.refresh_from_db()
        stale.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertEqual(stale.status, AnalysisStatus.FAILED)
        self.assertEqual(stale.error_message, STALE_RUN_MESSAGE)
        mock_run.assert_called_once()


# ---------------------------------------------------------------------------
# 자체 taint 엔진 — 1단계 함수 내 (docs/decisions.md 2026-09-06 custom-taint)
# ---------------------------------------------------------------------------

def _sinks(source):
    """소스 텍스트를 분석해 {(KISA 코드 끝 두 자리, 싱크 줄)} — 시험용 축약."""
    return {(f.kisa_code[-5:], f.sink['line']) for f in analyze_source(textwrap.dedent(source), 'app.py')}


def _traces(source):
    return {f.sink['line']: f for f in analyze_source(textwrap.dedent(source), 'app.py')}


class CustomTaintPropagationTests(SimpleTestCase):
    """전파 형태·소스 종류 — Django 없이 엔진만 (analysis/taint는 Django를 import하지 않는다)."""

    def test_variable_hops_and_trace(self):
        source = '''
            import os
            def f(host):
                cmd = "ping " + host
                line = cmd + " -c 1"
                os.system(line)
        '''
        finding = _traces(source)[6]
        self.assertEqual(finding.kisa_code, 'KISA-IV-05')
        self.assertEqual(finding.taint.kind, 'param')
        self.assertEqual(finding.taint.source['line'], 3)
        self.assertEqual([s['line'] for s in finding.taint.steps], [4, 5])
        self.assertEqual(finding.sink['code'], 'os.system(line)')

    def test_formatting_forms_propagate(self):
        source = '''
            import os
            def a(h): os.system(f"ping {h}")
            def b(h): os.system("ping %s" % h)
            def c(h): os.system("ping {}".format(h))
            def d(h): os.system(" ".join(["ping", h]))
            def e(h): os.system(str(h).strip().lower())
            def g(h): os.system({"k": h}["k"])
            def i(h): os.system(h if h else "x")
        '''
        self.assertEqual({line for _, line in _sinks(source)}, {3, 4, 5, 6, 7, 8, 9})

    def test_constants_and_list_args_are_not_flagged(self):
        source = '''
            import os, subprocess
            LOCAL = "127.0.0.1"
            def a():
                target = LOCAL
                os.system("ping " + target)
            def b(n):
                os.system(f"ping -c {3} localhost")
            def c(host):
                subprocess.run(["ping", host])
            def d(host):
                subprocess.run(["ping", host], shell=True)
        '''
        self.assertEqual(_sinks(source), {('IV-05', 12)})

    def test_request_inputs_are_input_sources_even_via_parameter(self):
        source = '''
            def a(request, cur):
                q = request.GET.get("q")
                cur.execute("SELECT " + q)
            def b(request, cur):
                cur.execute(request.POST["q"])
            def c(request):
                exec(request.body)
        '''
        traces = _traces(source)
        self.assertEqual({k: v.taint.kind for k, v in traces.items()}, {4: 'input', 6: 'input', 8: 'input'})
        self.assertEqual(traces[4].taint.source['line'], 3)

    def test_process_inputs_are_sources(self):
        source = '''
            import os, sys
            def a(): os.system(input())
            def b(): os.system(sys.argv[1])
            def c(): os.system(os.environ["CMD"])
            def d(): os.system(os.getenv("CMD"))
        '''
        self.assertEqual({line for _, line in _sinks(source)}, {3, 4, 5, 6})

    def test_self_and_cls_are_not_sources(self):
        source = '''
            import os
            class A:
                def run(self):
                    os.system(self.cmd)
                @classmethod
                def go(cls):
                    os.system(cls.cmd)
        '''
        self.assertEqual(_sinks(source), set())

    def test_every_sink_family(self):
        source = '''
            def s1(cur, q): cur.execute(q)
            def s2(x): eval(x)
            def s3(p): open(p)
            def s4(p): p.read_text()
            def s5(b): HttpResponse(b)
            def s6(b): HttpResponse(content=b)
            def s7(c): os.popen(c)
            def s8(u): redirect(u)
            def s9(u): requests.post(u)
            def s10(u): urllib.request.urlopen(u)
            def s11(u): httpx.get(u)
        '''
        self.assertEqual(
            _sinks(source),
            {('IV-01', 2), ('IV-02', 3), ('IV-03', 4), ('IV-03', 5), ('IV-04', 6), ('IV-04', 7),
             ('IV-05', 8), ('IV-07', 9), ('IV-12', 10), ('IV-12', 11), ('IV-12', 12)},
        )


class CustomTaintSanitizerTests(SimpleTestCase):
    """sanitizer·검사 가드 — safe.py의 매개변수 검증 8케이스와 같은 형태들."""

    def test_value_sanitizers(self):
        source = '''
            import os, shlex
            def a(h): os.system("ping " + shlex.quote(h))
            def b(p): os.system(f"nc {int(p)}")
            def c(n): open(os.path.join("/u", os.path.basename(n)))
            def d(n): open(Path(n).name)
            def e(x): HttpResponse("<b>" + escape(x) + "</b>")
            def f(h): os.system(validate_host(h))
            def g(h): os.system(self.sanitize_cmd(h))
        '''
        self.assertEqual(_sinks(source), set())

    def test_guards_clean_after_check(self):
        source = '''
            import os, re
            def a(host):
                if not re.fullmatch(r"[a-z]+", host):
                    raise ValueError
                os.system("ping " + host)
            def b(table, conn):
                if table not in ALLOWED:
                    raise ValueError
                conn.cursor().execute("SELECT * FROM " + table)
            def c(name):
                target = (ROOT / name).resolve()
                if not target.is_relative_to(ROOT):
                    raise ValueError
                return target.read_text()
            def d(url):
                if url_has_allowed_host_and_scheme(url, allowed_hosts=None):
                    return redirect(url)
            def e(x):
                if re.match(PAT, x) is None:
                    return
                eval(x)
            def f(x):
                pattern = re.compile("a")
                if not pattern.fullmatch(x):
                    return
                eval(x)
        '''
        self.assertEqual(_sinks(source), set())

    def test_guard_only_cleans_the_checked_variable(self):
        source = '''
            import os
            def a(host, other):
                if host in ALLOWED:
                    os.system("ping " + other)
        '''
        self.assertEqual(_sinks(source), {('IV-05', 5)})

    def test_unknown_escape_function_propagates(self):
        # 본문을 보지 않는 한계(1단계) — Semgrep과 같다. 2단계에서 같은 파일 함수는 요약으로 판단한다.
        source = '''
            import os
            def a(h): os.system(my_escape(h))
        '''
        self.assertEqual(_sinks(source), {('IV-05', 3)})


class CustomTaintControlFlowTests(SimpleTestCase):
    """경로 비민감 합집합·루프 상한(LOOP_PASSES)."""

    def test_taint_in_one_branch_is_kept(self):
        source = '''
            import os
            def a(flag, h):
                cmd = "ls"
                if flag:
                    cmd = "ping " + h
                os.system(cmd)
            def b(flag, h):
                cmd = h
                if flag:
                    cmd = "ls"
                os.system(cmd)
        '''
        self.assertEqual({line for _, line in _sinks(source)}, {7, 12})

    def test_try_with_and_for_target(self):
        source = '''
            import os
            def a(h):
                try:
                    cmd = "ping " + h
                except Exception:
                    cmd = "ls"
                os.system(cmd)
            def b(h):
                with make(h) as ctx:
                    os.system(ctx)
            def c(hosts):
                for h in hosts:
                    os.system(h)
        '''
        self.assertEqual({line for _, line in _sinks(source)}, {8, 11, 14})

    def test_loop_carried_chain_within_pass_limit(self):
        # 역방향 체인 a = b; b = 입력: 첫 바퀴에 b, 둘째 바퀴에 a — 상한 2로 잡힌다.
        source = '''
            import os
            def a(h):
                a = ""
                b = ""
                for _ in range(3):
                    a = b
                    b = h
                os.system(a)
        '''
        self.assertEqual(_sinks(source), {('IV-05', 9)})

    def test_loop_carried_chain_at_pass_limit_is_caught(self):
        # 3단계 역방향 체인(a = b; b = c; c = 입력)은 바퀴마다 한 단계씩 전파된다 — LOOP_PASSES=3이 잡는다.
        source = '''
            import os
            def a(h):
                a = b = c = ""
                for _ in range(3):
                    a = b
                    b = c
                    c = h
                os.system(a)
        '''
        self.assertEqual(LOOP_PASSES, 3)
        self.assertEqual(_sinks(source), {('IV-05', 9)})

    def test_loop_carried_chain_beyond_pass_limit_is_documented(self):
        # 4단계 체인은 상한 3에서 못 잡는다 — 알려진 한계(decisions.md). "여기서부터 못 잡는다"를 고정한다:
        # 상한을 바꾸거나 고정점으로 가면 이 시험이 알려준다.
        source = '''
            import os
            def a(h):
                a = b = c = d = ""
                for _ in range(4):
                    a = b
                    b = c
                    c = d
                    d = h
                os.system(a)
                os.system(b)
        '''
        found = {line for _, line in _sinks(source)}
        self.assertIn(11, found)       # b: 세 단계 — 잡힘
        self.assertNotIn(10, found)    # a: 네 단계 — 상한 3에서는 못 잡음

    def test_call_that_is_the_whole_header_expression_is_a_sink(self):
        # `with open(p) as f:`·`if eval(x):`·`for h in os.popen(c):` — 헤더 식 자체가 호출인 경우.
        # 자식 호출만 보던 첫 판이 자체 저장소의 `with open(path)` 6건을 통째로 놓쳤다.
        source = '''
            import os
            def a(p):
                with open(p, encoding="utf-8") as handle:
                    return handle.read()
            def b(x):
                if eval(x):
                    return 1
            def c(cmd):
                for line in os.popen(cmd):
                    pass
        '''
        self.assertEqual(_sinks(source), {('IV-03', 4), ('IV-02', 7), ('IV-05', 10)})

    def test_nested_function_is_analyzed_separately(self):
        source = '''
            import os
            def outer(h):
                def inner(x):
                    os.system(x)
                inner(h)
        '''
        self.assertEqual(_sinks(source), {('IV-05', 5)})


class CustomTaintEngineTests(SimpleTestCase):
    """디렉토리 진입점 — best-effort·예산·크기·제외·결과 모양."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp(prefix='custom-taint-'))
        self.addCleanup(shutil.rmtree, self.root, ignore_errors=True)

    def _write(self, rel, text):
        target = self.root / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(textwrap.dedent(text), encoding='utf-8')

    def test_items_look_like_semgrep_results_with_trace(self):
        self._write('pkg/app.py', '''
            import os
            def f(host):
                cmd = "ping " + host
                os.system(cmd)
        ''')
        result = analyze_directory(self.root)
        self.assertEqual(result['errors'], [])
        self.assertEqual(result['stats']['analyzed'], 1)
        item = result['results'][0]
        self.assertEqual(item['check_id'], 'custom-taint-kisa-iv-05')
        self.assertEqual(Path(item['path']), self.root / 'pkg' / 'app.py')
        self.assertEqual(item['start']['line'], 5)
        self.assertEqual(item['extra']['metadata'], {'kisa_code': 'KISA-IV-05', 'cwe': 'CWE-78', 'engine': 'custom-taint'})
        self.assertEqual(item['extra']['taint_trace'], {
            'source': {'path': 'pkg/app.py', 'line': 3, 'code': 'def f(host):'},
            'steps': [{'path': 'pkg/app.py', 'line': 4, 'code': 'cmd = "ping " + host'}],
            'sink': {'path': 'pkg/app.py', 'line': 5, 'code': 'os.system(cmd)'},
            'paths_count': 1,
        })

    def test_syntax_error_and_non_python_do_not_stop_the_run(self):
        self._write('bad.py', 'def (:\n')
        self._write('ok.py', 'import os\ndef f(h): os.system(h)\n')
        self._write('note.txt', 'os.system(x)')
        result = analyze_directory(self.root)
        self.assertEqual(result['stats']['files'], 2)
        self.assertEqual(result['stats']['parse_errors'], 1)
        self.assertEqual(len(result['results']), 1)
        self.assertTrue(result['errors'][0].startswith('bad.py: 문법 오류'))

    def test_budget_and_size_limits_skip_files(self):
        self._write('a.py', 'import os\ndef f(h): os.system(h)\n')
        self._write('b.py', 'import os\ndef f(h): os.system(h)\n')
        result = analyze_directory(self.root, time_budget=0)
        self.assertEqual(result['stats']['skipped_budget'], 2)
        self.assertEqual(result['results'], [])
        self.assertIn('시간 예산', result['errors'][0])
        result = analyze_directory(self.root, max_file_bytes=5)
        self.assertEqual(result['stats']['skipped_size'], 2)

    def test_exclusion_callback(self):
        self._write('vendor/x.py', 'import os\ndef f(h): os.system(h)\n')
        self._write('app.py', 'import os\ndef f(h): os.system(h)\n')
        result = analyze_directory(self.root, is_excluded=lambda parts: parts[0] == 'vendor')
        self.assertEqual(result['stats']['skipped_excluded'], 1)
        self.assertEqual([Path(i['path']).name for i in result['results']], ['app.py'])


class ExecuteAnalysisTests(AnalysisTestCase):
    """Semgrep → 자체 taint → 시그널 순서, best-effort, 설정 스위치."""

    def _run(self, entries):
        self.login(self.admin)
        response = self.client.post(
            list_url(self.project_a.pk), {'file': upload_file(entries=entries)}, format='multipart',
        )
        run = AnalysisRun.objects.get(pk=response.data['id'])
        self.assertTrue(mark_queued(run))
        self.assertTrue(start_run(run))
        return run

    @patch('analysis.services.subprocess.run')
    def test_custom_result_is_saved_after_semgrep(self, mock_run):
        run = self._run({'app.py': 'import os\ndef f(h):\n    c = h\n    os.system(c)\n'})
        _succeeding_semgrep(mock_run)
        execute_analysis(run)
        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertEqual(run.custom_result['stats']['analyzed'], 1)
        self.assertEqual(run.custom_result['results'][0]['start']['line'], 4)
        self.assertEqual(run.custom_result['errors'], [])

    @patch('analysis.services.subprocess.run')
    def test_semgrep_failure_skips_custom_engine(self, mock_run):
        run = self._run({'app.py': 'x = 1\n'})
        mock_run.return_value.returncode = 2
        mock_run.return_value.stdout = ''
        mock_run.return_value.stderr = 'boom'
        execute_analysis(run)
        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.FAILED)
        self.assertIsNone(run.custom_result)

    @patch('analysis.services.subprocess.run')
    def test_engine_crash_is_recorded_not_raised(self, mock_run):
        run = self._run({'app.py': 'x = 1\n'})
        _succeeding_semgrep(mock_run)
        with patch('analysis.services.analyze_directory', side_effect=RuntimeError('boom')):
            with self.assertLogs('analysis.services', level='ERROR'):
                execute_analysis(run)
        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertEqual(run.custom_result['results'], [])
        self.assertIn('RuntimeError', run.custom_result['errors'][0])

    @override_settings(ANALYSIS_CUSTOM_TAINT_ENABLED=False)
    @patch('analysis.services.subprocess.run')
    def test_disabled_engine_stores_none(self, mock_run):
        run = self._run({'app.py': 'import os\ndef f(h): os.system(h)\n'})
        _succeeding_semgrep(mock_run)
        execute_analysis(run)
        run.refresh_from_db()
        self.assertIsNone(run.custom_result)

    @patch('analysis.services.subprocess.run')
    def test_project_exclude_paths_apply_to_custom_engine(self, mock_run):
        self.project_a.exclude_paths = ['vendor']
        self.project_a.save()
        run = self._run({
            'app.py': 'import os\ndef f(h): os.system(h)\n',
            'vendor/lib.py': 'import os\ndef f(h): os.system(h)\n',
        })
        _succeeding_semgrep(mock_run)
        execute_analysis(run)
        run.refresh_from_db()
        self.assertEqual(run.custom_result['stats']['skipped_excluded'], 1)
        self.assertEqual(len(run.custom_result['results']), 1)

    @patch('analysis.services.subprocess.run')
    def test_run_detail_exposes_custom_taint_stats(self, mock_run):
        run = self._run({'app.py': 'import os\ndef f(h): os.system(h)\n'})
        _succeeding_semgrep(mock_run)
        execute_analysis(run)
        response = self.client.get(detail_url(run.pk))
        stats = response.data['custom_taint_stats']
        self.assertEqual(stats['analyzed'], 1)
        self.assertIn('semgrep_only', stats)  # 표준화가 병합 통계를 덧붙인다


# ---------------------------------------------------------------------------
# 자체 taint 엔진 — 2단계 같은 파일 함수 간 (docs/decisions.md 2026-09-06 custom-taint 2단계)
# ---------------------------------------------------------------------------

def _roles(finding):
    return [s.get('role') for s in finding.taint.steps]


class InterproceduralSummaryTests(SimpleTestCase):
    """함수 요약(매개변수→반환·매개변수→싱크·본문 안 입력→반환)과 고정점."""

    def test_return_chain_is_followed_with_full_trace(self):
        # 6단계 반환 체인 — 여러 줄 함수라 경로 노드가 전부 남는다.
        source = '''
            import os
            def c1(x):
                return c2(x)
            def c2(x):
                return c3(x)
            def c3(x):
                return c4(x)
            def c4(x):
                return c5(x)
            def c5(x):
                return c6(x)
            def c6(x):
                return "ping " + x
            def view(request):
                q = request.GET.get("q")
                os.system(c1(q))
        '''
        finding = _traces(source)[17]
        self.assertEqual(finding.taint.kind, 'input')
        self.assertEqual(finding.taint.source['line'], 16)
        self.assertEqual(
            [(s.get('role'), s['line']) for s in finding.taint.steps],
            [('call', 17), ('enter', 3), ('call', 4), ('enter', 5), ('call', 6), ('enter', 7), ('call', 8),
             ('enter', 9), ('call', 10), ('enter', 11), ('call', 12), ('enter', 13), ('return', 14)],
        )  # 되돌아오는 return 줄들은 이미 있는 call 줄과 같아 표시 중복이라 생략된다

    def test_chain_beyond_summary_pass_limit_is_documented(self):
        # SUMMARY_PASSES패스에 체인이 한 단계씩 번진다 — 상한-1 단계까지 완전하고 그보다 긴 체인은 놓친다.
        # "여기서부터 못 잡는다"를 고정: 상한을 바꾸면 이 시험이 알려준다.
        def chain(depth):
            funcs = ''.join(f'def c{i}(x):\n    return c{i + 1}(x)\n' for i in range(1, depth))
            funcs += f'def c{depth}(x):\n    return "ping " + x\n'
            return f'import os\n{funcs}def view(request):\n    os.system(c1(request.GET.get("q")))\n'
        self.assertEqual(SUMMARY_PASSES, 16)
        within = analyze_source(chain(SUMMARY_PASSES - 1), 'app.py')
        beyond = analyze_source(chain(SUMMARY_PASSES + 2), 'app.py')
        self.assertEqual(len(within), 1)
        self.assertEqual(len(beyond), 0)

    def test_direct_recursion_with_base_case_propagates(self):
        source = '''
            import os
            def rec(x, n):
                if n == 0:
                    return x
                return rec(x, n - 1)
            def view(request):
                os.system(rec(request.GET.get("q"), 3))
        '''
        self.assertEqual(_sinks(source), {('IV-05', 8)})

    def test_mutual_recursion_without_base_case_is_clean_and_terminates(self):
        # 요약이 아직 없는 함수는 빈 요약(전파 없음)으로 본다 — 영원히 돌아오지 않는 함수는 깨끗하다.
        source = '''
            import os
            def a(x):
                return b(x)
            def b(x):
                return a(x)
            def view(request):
                os.system(a(request.GET.get("q")))
        '''
        self.assertEqual(_sinks(source), set())

    def test_call_before_definition(self):
        source = '''
            import os
            def view(request):
                os.system(later(request.GET.get("q")))
            def later(x):
                return "ping " + x
        '''
        self.assertEqual(_sinks(source), {('IV-05', 4)})

    def test_keyword_arguments_map_to_parameters_and_defaults_are_constants(self):
        source = '''
            import os
            def build(prefix, host="localhost", flag="-c 1"):
                return prefix + host + flag
            def a(request):
                os.system(build("ping ", host=request.GET.get("h")))
            def b(request):
                os.system(build("ping ", flag=request.GET.get("f")))
            def c(request):
                os.system(build("ping "))
        '''
        self.assertEqual({line for _, line in _sinks(source)}, {6, 8})

    def test_body_beats_name_convention_for_module_functions(self):
        source = '''
            import os
            def sanitize_cmd(x):
                return x
            def validate_host(h):
                if h not in ALLOWED:
                    raise ValueError
                return h
            def clean(x):
                return int(x)
            def discard(x):
                log(x)
                return "ok"
            def lie(request):
                os.system(sanitize_cmd(request.GET.get("q")))
            def honest(request):
                os.system(validate_host(request.GET.get("h")))
            def body_clean(request):
                os.system(f"nc {clean(request.GET.get('p'))}")
            def body_discard(request):
                os.system(discard(request.GET.get("q")))
            def imported(request):
                os.system(sanitize_external(request.GET.get("q")))
        '''
        # 이름이 거짓말하는 sanitize_cmd만 잡히고, 본문이 씻는 세 헬퍼는 깨끗. 정의가 없는 sanitize_external은
        # 이름 규약이 그대로 적용된다.
        self.assertEqual(_sinks(source), {('IV-05', 15)})

    def test_input_inside_helper_reaches_caller_sink(self):
        source = '''
            import os
            def read_cmd():
                line = input()
                return line
            def cfg():
                return os.environ["CMD"]
            def a():
                os.system(read_cmd())
            def b():
                target = cfg()
                os.system(target)
        '''
        traces = _traces(source)
        self.assertEqual(set(traces), {9, 12})
        self.assertEqual(traces[9].taint.source['line'], 4)
        self.assertEqual(_roles(traces[12]), ['return'])  # cfg() 호출 줄(= 대입 줄)로 돌아온다

    def test_helper_sink_reported_with_caller_origin_and_paths_count(self):
        source = '''
            import os
            def run(cmd):
                os.system(cmd)
            def a(request):
                q = request.GET.get("q")
                run(q)
            def b(other):
                run(other)
        '''
        finding = _traces(source)[4]
        self.assertEqual(finding.taint.kind, 'input')
        self.assertEqual(finding.taint.source['line'], 6)
        self.assertEqual([(s.get('role'), s['line']) for s in finding.taint.steps], [('call', 7), ('enter', 3)])
        self.assertEqual(finding.paths_count, 3)  # run 자신(매개변수) + 호출자 2

    def test_same_kind_prefers_longer_trace(self):
        source = '''
            import os
            def run(cmd):
                os.system(cmd)
            def caller(value):
                cmd = "ping " + value
                run(cmd)
        '''
        finding = _traces(source)[4]
        self.assertEqual(finding.taint.kind, 'param')
        self.assertEqual(finding.taint.source['line'], 5)  # caller의 def — 경로가 더 길다

    def test_redefinition_uses_last_definition(self):
        source = '''
            import os
            def helper(x):
                return "ok"
            def helper(x):
                return x
            def view(request):
                os.system(helper(request.GET.get("q")))
        '''
        self.assertEqual(_sinks(source), {('IV-05', 8)})

    def test_nested_function_is_an_unknown_call(self):
        source = '''
            import os
            def view(request):
                def helper(x):
                    return "ok"
                os.system(helper(request.GET.get("q")))
        '''
        self.assertEqual(_sinks(source), {('IV-05', 6)})  # 클로저는 요약에 없어 모르는 호출로 전파(범위 밖)

    def test_method_call_chain_target_is_a_sink(self):
        # `conn.cursor().execute(...)` — 대상이 호출 결과여도 끝 이름으로 싱크가 맞는다(2단계 샘플에서 빠졌던 형태).
        source = '''
            def q(conn, request):
                conn.cursor().execute("SELECT " + request.GET.get("q"))
        '''
        self.assertEqual(_sinks(source), {('IV-01', 3)})

    def test_mutual_recursion_with_multiple_returns_converges_below_cap(self):
        # Django db/models/sql/query.py의 rename_prefix_from_q ↔ get_child_with_renamed_prefix 형태 — 새 요약만 쓰면
        # 대표 경로가 패스마다 바뀌어(경유 5 ↔ 8) 상한 16까지 진동했다. 요약을 이전 패스와 합쳐(긴 경로 유지) 단조로
        # 만든 뒤에는 몇 패스 안에 멈춘다.
        root = Path(tempfile.mkdtemp(prefix='custom-taint-'))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / 'app.py').write_text(textwrap.dedent('''
            import os
            def rename(prefix, child):
                if isinstance(child, list):
                    return rename_all(prefix, child)
                if isinstance(child, tuple):
                    lhs, rhs = child
                    if lhs.startswith(prefix):
                        lhs = lhs.replace(prefix, "x", 1)
                    rhs = rename(prefix, rhs)
                    return lhs, rhs
                return child
            def rename_all(prefix, q):
                return [rename(prefix, c) for c in q]
            def view(request):
                os.system(rename(request.GET.get("p"), request.GET.get("c")))
        '''), encoding='utf-8')
        result = analyze_directory(root)
        self.assertLess(result['stats']['summary_passes'], SUMMARY_PASSES)
        self.assertEqual([i['start']['line'] for i in result['results']], [16])

    def test_engine_reports_summary_passes(self):
        root = Path(tempfile.mkdtemp(prefix='custom-taint-'))
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        (root / 'app.py').write_text('import os\ndef a(x):\n    return b(x)\ndef b(x):\n    return x\ndef v(r):\n    os.system(a(r.GET.get("q")))\n', encoding='utf-8')
        result = analyze_directory(root)
        # a→b 체인 + v의 요약이 a의 경로를 이어받아 자라므로 3~4패스에 안정된다. 상한에는 닿지 않는다.
        self.assertGreaterEqual(result['stats']['summary_passes'], 3)
        self.assertLess(result['stats']['summary_passes'], SUMMARY_PASSES)
