"""진단 기준·결과 표준화 시험 (TST-005, TST-006, TST-007, QLT-004).

핵심 네 가지:
1. 정탐·오탐 — 취약 샘플에서 구현된 전 룰(IMPLEMENTED_CODES)이 걸리고,
   안전 샘플에서는 0건이다 (TST-005).
2. 심각도 정규화 — 카탈로그 등급이 Semgrep 등급을 이긴다. 말이 아니라 두 값이
   실제로 충돌하는 케이스로 증명한다 (QLT-004).
3. 경로 노출 — 저장값·응답 어디에도 서버 절대경로·workspace UUID가 없다 (SEC-006/007).
4. IDOR — projects·analysis와 같은 원칙으로, run id를 조작해도 할당되지 않은
   프로젝트의 결과에는 닿을 수 없다 (SEC-005).

Semgrep을 실제로 돌리는 시험은 바이너리가 있을 때만 수행한다(skipUnless). 나머지는
subprocess를 모킹하거나 raw_result를 직접 넣어, 바이너리 유무와 무관하게 돈다.
"""

import json
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from django.conf import settings
from django.contrib.auth import get_user_model
from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import SimpleTestCase, TestCase, override_settings
from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from accounts.models import Role
from analysis.models import AnalysisRun, AnalysisStatus
from analysis.services import run_semgrep, source_dir
from analysis.signals import run_succeeded
from projects.models import Project, ProjectMember

from .models import DiagnosticRule, Finding, KisaCategory, Severity
from .services import bare_check_id, ingest_findings, normalize_severity
from .views import FindingPagination

User = get_user_model()
PASSWORD = 'sast-test-pw-9182'

SAMPLES_DIR = Path(settings.BASE_DIR) / 'catalog' / 'samples'

# add_finding()에서 "인자를 주지 않음"과 "명시적으로 None(미매핑)"을 구분하기 위한 센티널.
_UNSET = object()

# KISA 가이드 2021.11 기준 유형별 항목 수. 시드 데이터가 가이드와 어긋나면 여기서
# 걸린다 — 총합 49만 맞추고 분포가 틀리는 것을 막는다.
CATEGORY_COUNTS = {'IV': 17, 'SF': 16, 'TS': 2, 'EH': 3, 'CE': 5, 'EN': 4, 'AA': 2}
SEVERITY_COUNTS = {'HIGH': 26, 'MEDIUM': 20, 'LOW': 3}

# 실탐지 룰이 붙은 항목 (선정 근거는 docs/decisions.md — 8/27 최초 13개, 8/29 확장).
IMPLEMENTED_CODES = {
    'KISA-IV-01', 'KISA-IV-02', 'KISA-IV-03', 'KISA-IV-05', 'KISA-IV-11', 'KISA-IV-12',
    'KISA-SF-04', 'KISA-SF-06', 'KISA-SF-08', 'KISA-SF-11', 'KISA-SF-14',
    'KISA-CE-02', 'KISA-CE-05', 'KISA-EH-01', 'KISA-EH-03', 'KISA-EN-02',
    'KISA-AA-02',
}
# 취약 샘플에서 나와야 하는 룰별 건수. 총 26건.
EXPECTED_SAMPLE_FINDINGS = {
    'KISA-IV-01': 1, 'KISA-IV-02': 1, 'KISA-IV-03': 1, 'KISA-IV-05': 2, 'KISA-IV-11': 1,
    'KISA-IV-12': 2,
    'KISA-SF-04': 1, 'KISA-SF-06': 2, 'KISA-SF-08': 1, 'KISA-SF-11': 2, 'KISA-SF-14': 1,
    'KISA-CE-02': 1, 'KISA-CE-05': 2, 'KISA-EH-01': 2, 'KISA-EH-03': 2, 'KISA-EN-02': 2,
    'KISA-AA-02': 2,
}

SEMGREP_AVAILABLE = shutil.which('semgrep') is not None


def seed():
    call_command('seed_catalog', verbosity=0)


def rule_list_url():
    return reverse('catalog:rule-list')


def rule_detail_url(code):
    return reverse('catalog:rule-detail', args=[code])


def catalog_summary_url():
    return reverse('catalog:catalog-summary')


def findings_url(run_id):
    return reverse('catalog:run-finding-list', args=[run_id])


def findings_summary_url(run_id):
    return reverse('catalog:run-finding-summary', args=[run_id])


def reingest_url(run_id):
    return reverse('catalog:run-finding-reingest', args=[run_id])


def semgrep_result(path, kisa_code, line=1, severity='ERROR', check_id=None, message='m'):
    """Semgrep --json 결과 1건의 형태. check_id의 config 경로 접두사까지 재현한다."""
    return {
        'check_id': check_id or f'catalog.rules.{kisa_code.lower()}-rule',
        'path': str(path),
        'start': {'line': line},
        'end': {'line': line},
        'extra': {
            'severity': severity,
            'message': message,
            # Semgrep은 미인증 상태에서 코드 조각을 가려서 준다 — 우리가 파일에서
            # 직접 읽는 이유다 (docs/decisions.md).
            'lines': 'requires login',
            'metadata': {'kisa_code': kisa_code, 'cwe': 'CWE-000'},
        },
    }


class WorkspaceMixin:
    """격리 디렉토리를 임시 경로로 돌린다 — 테스트가 실제 media/를 더럽히지 않게."""

    def setup_workspace(self):
        tmp_root = Path(tempfile.mkdtemp(prefix='catalog-tests-'))
        self.addCleanup(shutil.rmtree, tmp_root, ignore_errors=True)
        overridden = override_settings(ANALYSIS_WORKSPACE_ROOT=tmp_root)
        overridden.enable()
        self.addCleanup(overridden.disable)

    def make_run(self, project, user, status_value=AnalysisStatus.SUCCEEDED, raw_result=None):
        run = AnalysisRun.objects.create(
            project=project, created_by=user, original_filename='demo.zip',
            status=status_value, raw_result=raw_result,
        )
        source_dir(run).mkdir(parents=True, exist_ok=True)
        return run

    def write_source(self, run, relative_path, content):
        target = source_dir(run) / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')
        return target


# ---------------------------------------------------------------------------
# 시드 (SFR-012, SFR-013, DAR-007)
# ---------------------------------------------------------------------------

class SeedCatalogTests(TestCase):
    """카탈로그 등록이 가이드와 일치하고 재실행에 안전한가 (TST-006)."""

    def setUp(self):
        super().setUp()
        seed()

    def test_registers_all_49_rules(self):
        self.assertEqual(DiagnosticRule.objects.count(), 49)

    def test_category_distribution_matches_guide(self):
        actual = {
            value: DiagnosticRule.objects.filter(category=value).count()
            for value in KisaCategory.values
        }
        self.assertEqual(actual, CATEGORY_COUNTS)

    def test_severity_distribution_matches_decisions(self):
        actual = {
            value: DiagnosticRule.objects.filter(severity=value).count()
            for value in Severity.values
        }
        self.assertEqual(actual, SEVERITY_COUNTS)

    def test_codes_are_unique(self):
        codes = list(DiagnosticRule.objects.values_list('code', flat=True))
        self.assertEqual(len(codes), len(set(codes)))

    def test_code_prefix_matches_category(self):
        for rule in DiagnosticRule.objects.all():
            self.assertEqual(rule.code.split('-')[1], rule.category, rule.code)

    def test_running_twice_does_not_duplicate(self):
        seed()
        seed()
        self.assertEqual(DiagnosticRule.objects.count(), 49)

    def test_only_rules_with_yaml_are_implemented(self):
        implemented = set(
            DiagnosticRule.objects.implemented().values_list('code', flat=True)
        )
        self.assertEqual(implemented, IMPLEMENTED_CODES)

    def test_implemented_queryset_agrees_with_property(self):
        """쿼리셋 판정과 프로퍼티 판정이 갈라지면 필터 결과와 상세 표시가 어긋난다."""
        for rule in DiagnosticRule.objects.all():
            self.assertEqual(rule.is_implemented, rule.code in IMPLEMENTED_CODES, rule.code)

    def test_implemented_rules_carry_severity_reason(self):
        """등급 근거 없이 등급만 남는 것을 막는다 (QLT-004)."""
        for rule in DiagnosticRule.objects.implemented():
            self.assertTrue(rule.severity_reason.strip(), rule.code)


class SeedValidationTests(TestCase):
    """잘못된 시드·룰은 조용히 통과하지 않고 실패한다."""

    def _rules_dir(self, filename, body):
        tmp = Path(tempfile.mkdtemp(prefix='catalog-rules-'))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        (tmp / filename).write_text(body, encoding='utf-8')
        return tmp

    def _seed_file(self, payload):
        tmp = Path(tempfile.mkdtemp(prefix='catalog-seed-'))
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        path = tmp / 'seed.json'
        path.write_text(json.dumps(payload), encoding='utf-8')
        return path

    def test_rejects_rule_pointing_to_unknown_code(self):
        """kisa_code 오타를 두면 탐지는 되는데 폴백 등급으로 조용히 저장된다."""
        rules_dir = self._rules_dir('typo.yaml', (
            'rules:\n'
            '  - id: kisa-iv-99-typo\n'
            '    languages: [python]\n'
            '    severity: ERROR\n'
            '    message: typo\n'
            '    metadata:\n'
            '      kisa_code: KISA-IV-99\n'
            '    pattern: eval(...)\n'
        ))
        with override_settings(CATALOG_RULES_DIR=rules_dir):
            with self.assertRaises(CommandError) as caught:
                call_command('seed_catalog', verbosity=0)
        self.assertIn('KISA-IV-99', str(caught.exception))

    def test_rejects_rule_without_kisa_code(self):
        rules_dir = self._rules_dir('nocode.yaml', (
            'rules:\n'
            '  - id: kisa-no-code\n'
            '    languages: [python]\n'
            '    severity: ERROR\n'
            '    message: no code\n'
            '    pattern: eval(...)\n'
        ))
        with override_settings(CATALOG_RULES_DIR=rules_dir):
            with self.assertRaises(CommandError) as caught:
                call_command('seed_catalog', verbosity=0)
        self.assertIn('kisa_code', str(caught.exception))

    def test_rejects_total_mismatch(self):
        """항목 누락·중복 추가를 선언값으로 잡는다."""
        seed_file = self._seed_file({
            'total': 49,
            'rules': [{'code': 'KISA-IV-01', 'name': 'x', 'category': 'IV',
                       'severity': 'HIGH'}],
        })
        with override_settings(CATALOG_SEED_FILE=seed_file):
            with self.assertRaises(CommandError) as caught:
                call_command('seed_catalog', verbosity=0)
        self.assertIn('total', str(caught.exception))

    def test_rejects_unknown_severity(self):
        seed_file = self._seed_file({
            'total': 1,
            'rules': [{'code': 'KISA-IV-01', 'name': 'x', 'category': 'IV',
                       'severity': 'CRITICAL'}],
        })
        with override_settings(CATALOG_SEED_FILE=seed_file):
            with self.assertRaises(CommandError):
                call_command('seed_catalog', verbosity=0)

    def test_rejects_unknown_category(self):
        seed_file = self._seed_file({
            'total': 1,
            'rules': [{'code': 'KISA-XX-01', 'name': 'x', 'category': 'XX',
                       'severity': 'HIGH'}],
        })
        with override_settings(CATALOG_SEED_FILE=seed_file):
            with self.assertRaises(CommandError):
                call_command('seed_catalog', verbosity=0)

    def test_rejects_duplicated_code(self):
        seed_file = self._seed_file({
            'total': 2,
            'rules': [
                {'code': 'KISA-IV-01', 'name': 'x', 'category': 'IV', 'severity': 'HIGH'},
                {'code': 'KISA-IV-01', 'name': 'y', 'category': 'IV', 'severity': 'LOW'},
            ],
        })
        with override_settings(CATALOG_SEED_FILE=seed_file):
            with self.assertRaises(CommandError):
                call_command('seed_catalog', verbosity=0)

    def test_dry_run_does_not_write(self):
        call_command('seed_catalog', '--dry-run', verbosity=0)
        self.assertEqual(DiagnosticRule.objects.count(), 0)


# ---------------------------------------------------------------------------
# 심각도 정규화 (QLT-004)
# ---------------------------------------------------------------------------

class SeverityNormalizationTests(TestCase):
    """카탈로그 등급이 메인, Semgrep 등급은 미매핑 시 폴백."""

    def setUp(self):
        super().setUp()
        seed()

    def test_catalog_severity_wins_when_mapped(self):
        rule = DiagnosticRule.objects.get(code='KISA-EH-01')
        self.assertEqual(rule.severity, Severity.MEDIUM)
        # Semgrep이 뭐라고 하든 카탈로그 등급이 최종이다.
        for reported in ('ERROR', 'WARNING', 'INFO', '', None):
            self.assertEqual(normalize_severity(rule, reported), Severity.MEDIUM)

    def test_fallback_table_applies_only_when_unmapped(self):
        self.assertEqual(normalize_severity(None, 'ERROR'), Severity.HIGH)
        self.assertEqual(normalize_severity(None, 'WARNING'), Severity.MEDIUM)
        self.assertEqual(normalize_severity(None, 'INFO'), Severity.LOW)

    def test_fallback_is_case_insensitive(self):
        self.assertEqual(normalize_severity(None, ' error '), Severity.HIGH)

    def test_unknown_severity_defaults_to_medium_not_low(self):
        """모를 때 낮게 매기면 실제 취약점이 목록 아래로 묻힌다 — 안전한 기본값."""
        self.assertEqual(normalize_severity(None, 'CRITICAL'), Severity.MEDIUM)
        self.assertEqual(normalize_severity(None, ''), Severity.MEDIUM)
        self.assertEqual(normalize_severity(None, None), Severity.MEDIUM)


class BareCheckIdTests(SimpleTestCase):
    """check_id에 설정 경로가 섞여 저장되지 않는다 (SEC-006)."""

    def test_strips_config_path_prefix(self):
        self.assertEqual(
            bare_check_id('catalog.rules.kisa-iv-01-sql-injection'),
            'kisa-iv-01-sql-injection',
        )

    def test_strips_absolute_windows_path(self):
        self.assertEqual(
            bare_check_id(r'C:\Users\someone\sast\catalog\rules.kisa-iv-01-sql-injection'),
            'kisa-iv-01-sql-injection',
        )

    def test_strips_posix_path(self):
        self.assertEqual(
            bare_check_id('/srv/app/catalog/rules/kisa-iv-01-sql-injection'),
            'kisa-iv-01-sql-injection',
        )

    def test_handles_missing_check_id(self):
        self.assertEqual(bare_check_id(None), '')


# ---------------------------------------------------------------------------
# 표준화 (SFR-014, DAR-006)
# ---------------------------------------------------------------------------

class IngestTests(WorkspaceMixin, TestCase):
    """raw_result → Finding 변환."""

    def setUp(self):
        super().setUp()
        seed()
        self.setup_workspace()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.project = Project.objects.create(name='p', created_by=self.admin)
        self.run = self.make_run(self.project, self.admin)

    def ingest(self, results):
        self.run.raw_result = {'results': results}
        self.run.save(update_fields=['raw_result'])
        return ingest_findings(self.run)

    def test_creates_finding_with_catalog_snapshot(self):
        target = self.write_source(self.run, 'app/db.py', 'q = 1\n')
        self.ingest([semgrep_result(target, 'KISA-IV-01')])

        finding = Finding.objects.get(run=self.run)
        rule = DiagnosticRule.objects.get(code='KISA-IV-01')
        self.assertEqual(finding.rule, rule)
        self.assertEqual(finding.rule_code, rule.code)
        self.assertEqual(finding.rule_name, rule.name)
        self.assertEqual(finding.severity, rule.severity)

    def test_records_original_semgrep_severity_for_comparison(self):
        """최종 등급이 카탈로그에서 왔다는 것을 결과만 보고 대조할 수 있어야 한다."""
        target = self.write_source(self.run, 'app/views.py', 'DEBUG = True\n')
        self.ingest([semgrep_result(target, 'KISA-EH-01', severity='ERROR')])

        finding = Finding.objects.get(run=self.run)
        self.assertEqual(finding.extra['semgrep_severity'], 'ERROR')
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_is_idempotent(self):
        target = self.write_source(self.run, 'app/db.py', 'q = 1\n')
        results = [semgrep_result(target, 'KISA-IV-01')]
        self.ingest(results)
        self.ingest(results)
        self.assertEqual(Finding.objects.filter(run=self.run).count(), 1)

    def test_unmapped_finding_is_kept_with_claimed_code(self):
        """탐지 결과가 조용히 사라지는 것보다 폴백 등급으로 남기는 편이 안전하다."""
        target = self.write_source(self.run, 'app/x.py', 'x = 1\n')
        result = self.ingest([semgrep_result(target, 'KISA-ZZ-99', severity='WARNING')])

        finding = Finding.objects.get(run=self.run)
        self.assertEqual(result.unmapped, 1)
        self.assertIsNone(finding.rule)
        self.assertEqual(finding.rule_code, 'KISA-ZZ-99')
        self.assertEqual(finding.rule_name, '')
        self.assertEqual(finding.severity, Severity.MEDIUM)

    def test_check_id_is_stored_without_config_prefix(self):
        target = self.write_source(self.run, 'app/db.py', 'q = 1\n')
        self.ingest([semgrep_result(
            target, 'KISA-IV-01', check_id='catalog.rules.kisa-iv-01-sql-injection',
        )])
        finding = Finding.objects.get(run=self.run)
        self.assertEqual(finding.semgrep_check_id, 'kisa-iv-01-sql-injection')
        self.assertIn(finding.semgrep_check_id, finding.rule.semgrep_rule_ids)

    def test_snippet_is_read_from_file_not_semgrep(self):
        """Semgrep이 조각을 'requires login'으로 가리므로 우리가 직접 읽는다."""
        target = self.write_source(self.run, 'app/db.py', 'a = 1\nb = 2\nc = 3\n')
        self.ingest([semgrep_result(target, 'KISA-IV-01', line=2)])
        self.assertEqual(Finding.objects.get(run=self.run).code_snippet, 'b = 2')

    def test_long_line_is_truncated(self):
        target = self.write_source(self.run, 'app/long.py', 'x = "' + 'A' * 50_000 + '"\n')
        self.ingest([semgrep_result(target, 'KISA-IV-01')])
        self.assertEqual(len(Finding.objects.get(run=self.run).code_snippet), 500)

    def test_snippet_skipped_for_oversized_file(self):
        """줄 수를 제한해도 한 줄의 길이는 제한되지 않으므로 크기부터 본다."""
        oversized = 'x = "' + 'A' * (2 * 1024 * 1024 + 1000) + '"\n'
        target = self.write_source(self.run, 'app/huge.py', oversized)
        self.ingest([semgrep_result(target, 'KISA-IV-01')])

        finding = Finding.objects.get(run=self.run)
        self.assertEqual(finding.code_snippet, '')
        # 조각은 없어도 결과 자체는 남는다.
        self.assertEqual(finding.rule_code, 'KISA-IV-01')

    def test_same_location_reads_file_once(self):
        target = self.write_source(self.run, 'app/multi.py', 'import pdb\npdb.set_trace()\n')
        opened = []
        original_open = Path.open

        def counting_open(path_self, *args, **kwargs):
            opened.append(str(path_self))
            return original_open(path_self, *args, **kwargs)

        with patch.object(Path, 'open', counting_open):
            self.ingest([
                semgrep_result(target, 'KISA-EN-02', line=2),
                semgrep_result(target, 'KISA-IV-02', line=2),
                semgrep_result(target, 'KISA-IV-01', line=2),
            ])

        self.assertEqual(len([p for p in opened if p.endswith('multi.py')]), 1)
        self.assertEqual(Finding.objects.filter(run=self.run).count(), 3)

    def test_finding_outside_workspace_is_skipped(self):
        """격리 루트 밖 경로는 신뢰하지 않는다 (SEC-007)."""
        result = self.ingest([
            semgrep_result(r'C:\Windows\System32\drivers\etc\hosts', 'KISA-IV-01'),
        ])
        self.assertEqual(result.created, 0)
        self.assertEqual(result.skipped, 1)
        self.assertEqual(Finding.objects.filter(run=self.run).count(), 0)

    def test_empty_raw_result_clears_previous_findings(self):
        target = self.write_source(self.run, 'app/db.py', 'q = 1\n')
        self.ingest([semgrep_result(target, 'KISA-IV-01')])
        self.ingest([])
        self.assertEqual(Finding.objects.filter(run=self.run).count(), 0)

    def test_reingest_maps_code_that_was_unknown_before(self):
        """룰·카탈로그를 고친 뒤 과거 분석에 반영하는 것이 재표준화의 목적이다."""
        target = self.write_source(self.run, 'app/x.py', 'x = 1\n')
        DiagnosticRule.objects.filter(code='KISA-IV-01').delete()
        self.ingest([semgrep_result(target, 'KISA-IV-01')])
        self.assertIsNone(Finding.objects.get(run=self.run).rule)

        seed()
        ingest_findings(self.run)
        finding = Finding.objects.get(run=self.run)
        self.assertIsNotNone(finding.rule)
        self.assertEqual(finding.severity, Severity.HIGH)


class PathDisclosureTests(WorkspaceMixin, TestCase):
    """저장값에 서버 내부 경로가 남지 않는다 (SEC-006, SEC-007)."""

    def setUp(self):
        super().setUp()
        seed()
        self.setup_workspace()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.project = Project.objects.create(name='p', created_by=self.admin)
        self.run = self.make_run(self.project, self.admin)
        target = self.write_source(self.run, 'src/app/db.py', 'q = 1\n')
        self.run.raw_result = {'results': [semgrep_result(target, 'KISA-IV-01')]}
        self.run.save(update_fields=['raw_result'])
        ingest_findings(self.run)
        self.finding = Finding.objects.get(run=self.run)

    def test_file_path_is_relative_to_workspace(self):
        self.assertEqual(self.finding.file_path, 'src/app/db.py')
        self.assertFalse(Path(self.finding.file_path).is_absolute())

    def test_stored_values_do_not_contain_workspace_root(self):
        blob = json.dumps({
            'file_path': self.finding.file_path,
            'check_id': self.finding.semgrep_check_id,
            'snippet': self.finding.code_snippet,
            'extra': self.finding.extra,
        })
        self.assertNotIn(str(settings.ANALYSIS_WORKSPACE_ROOT), blob)
        self.assertNotIn(str(self.run.workspace_id), blob)

    def test_check_id_has_no_path_separator(self):
        self.assertNotRegex(self.finding.semgrep_check_id, r'[\\/.]')


# ---------------------------------------------------------------------------
# API 공통
# ---------------------------------------------------------------------------

class CatalogApiTestCase(WorkspaceMixin, APITestCase):
    """관리자 1명, 할당된 일반 사용자 1명, 미할당 일반 사용자 1명."""

    def setUp(self):
        super().setUp()
        seed()
        self.setup_workspace()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.member = User.objects.create_user(email='member@example.com', password=PASSWORD)
        self.outsider = User.objects.create_user(email='outsider@example.com',
                                                 password=PASSWORD)

        self.project = Project.objects.create(name='할당된 프로젝트', created_by=self.admin)
        self.other_project = Project.objects.create(name='미할당 프로젝트',
                                                    created_by=self.admin)
        ProjectMember.objects.create(
            project=self.project, user=self.member, assigned_by=self.admin,
        )

        self.run = self.make_run(self.project, self.admin, raw_result={'results': []})
        self.other_run = self.make_run(self.other_project, self.admin,
                                       raw_result={'results': []})
        self.missing_run_id = AnalysisRun.objects.order_by('-pk').first().pk + 1000

        self.sql_rule = DiagnosticRule.objects.get(code='KISA-IV-01')     # HIGH / IV
        self.debug_rule = DiagnosticRule.objects.get(code='KISA-EN-02')   # MEDIUM / EN

    def login(self, user):
        self.client.force_authenticate(user=user)

    def add_finding(self, run=None, rule=_UNSET, **kwargs):
        """rule을 생략하면 SQL 삽입 항목, 명시적으로 None을 주면 미매핑 결과."""
        rule = self.sql_rule if rule is _UNSET else rule
        defaults = {
            'run': run or self.run,
            'rule': rule,
            'rule_code': rule.code if rule else '',
            'rule_name': rule.name if rule else '',
            'severity': rule.severity if rule else Severity.MEDIUM,
            'semgrep_check_id': 'k',
            'file_path': 'app/mod.py',
            'start_line': 1,
            'end_line': 1,
            'message': 'm',
            'extra': {},
        }
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)


class UnauthenticatedTests(CatalogApiTestCase):
    """SEC-002 — 인증 없이는 아무것도 열리지 않는다."""

    def test_catalog_list_requires_authentication(self):
        self.assertEqual(self.client.get(rule_list_url()).status_code,
                         status.HTTP_401_UNAUTHORIZED)

    def test_catalog_summary_requires_authentication(self):
        self.assertEqual(self.client.get(catalog_summary_url()).status_code,
                         status.HTTP_401_UNAUTHORIZED)

    def test_findings_require_authentication(self):
        self.assertEqual(self.client.get(findings_url(self.run.pk)).status_code,
                         status.HTTP_401_UNAUTHORIZED)

    def test_reingest_requires_authentication(self):
        self.assertEqual(self.client.post(reingest_url(self.run.pk)).status_code,
                         status.HTTP_401_UNAUTHORIZED)


class CatalogReadTests(CatalogApiTestCase):
    """진단 기준 조회 (SFR-013, TST-006)."""

    def test_regular_user_sees_all_49_rules(self):
        """카탈로그는 프로젝트에 딸린 데이터가 아니라 공통 기준 문서다."""
        self.login(self.member)
        response = self.client.get(rule_list_url())
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data), 49)

    def test_filters_by_category(self):
        self.login(self.member)
        self.assertEqual(len(self.client.get(rule_list_url(), {'category': 'IV'}).data),
                         CATEGORY_COUNTS['IV'])

    def test_filters_by_severity(self):
        self.login(self.member)
        self.assertEqual(len(self.client.get(rule_list_url(), {'severity': 'HIGH'}).data),
                         SEVERITY_COUNTS['HIGH'])

    def test_filters_by_implemented(self):
        self.login(self.member)
        implemented = self.client.get(rule_list_url(), {'implemented': 'true'})
        pending = self.client.get(rule_list_url(), {'implemented': 'false'})
        self.assertEqual(len(implemented.data), len(IMPLEMENTED_CODES))
        self.assertEqual(len(pending.data), 49 - len(IMPLEMENTED_CODES))

    def test_keyword_search(self):
        self.login(self.member)
        codes = [row['code'] for row in self.client.get(rule_list_url(), {'q': 'SQL'}).data]
        self.assertIn('KISA-IV-01', codes)

    def test_detail_is_looked_up_by_code(self):
        self.login(self.member)
        response = self.client.get(rule_detail_url('KISA-IV-01'))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['code'], 'KISA-IV-01')
        self.assertTrue(response.data['is_implemented'])
        self.assertTrue(response.data['severity_reason'])

    def test_unknown_code_is_404(self):
        self.login(self.member)
        self.assertEqual(self.client.get(rule_detail_url('KISA-ZZ-99')).status_code,
                         status.HTTP_404_NOT_FOUND)

    def test_summary_reports_implementation_status(self):
        self.login(self.member)
        data = self.client.get(catalog_summary_url()).data
        self.assertEqual(data['total'], 49)
        self.assertEqual(data['implemented'], len(IMPLEMENTED_CODES))
        self.assertEqual(data['not_implemented'], 49 - len(IMPLEMENTED_CODES))
        self.assertEqual(len(data['by_category']), 7)
        self.assertEqual(len(data['by_severity']), 3)

    def test_catalog_is_read_only(self):
        """시드 커맨드로만 바뀌는 데이터라 쓰기 라우트가 없다."""
        self.login(self.admin)
        self.assertEqual(self.client.post(rule_list_url(), {'code': 'X'}).status_code,
                         status.HTTP_405_METHOD_NOT_ALLOWED)


class FilterValidationTests(CatalogApiTestCase):
    """잘못된 필터는 조용히 무시되지 않는다.

    무시하면 오타 난 필터가 '전체 조회'가 되고, 빈 결과를 주면 '취약점 없음'으로
    오해된다 — 보안 도구에서 둘 다 위험한 실패 방식이다.
    """

    def test_unknown_category_is_rejected(self):
        self.login(self.member)
        self.assertEqual(self.client.get(rule_list_url(), {'category': 'XX'}).status_code,
                         status.HTTP_400_BAD_REQUEST)

    def test_unknown_severity_is_rejected(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(rule_list_url(), {'severity': 'CRITICAL'}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_non_boolean_implemented_is_rejected(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(rule_list_url(), {'implemented': 'maybe'}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )

    def test_unknown_severity_on_findings_is_rejected(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(findings_url(self.run.pk), {'severity': 'XX'}).status_code,
            status.HTTP_400_BAD_REQUEST,
        )


class FindingReadTests(CatalogApiTestCase):
    """진단 결과 조회·필터 (SFR-016, SFR-017, TST-007)."""

    def setUp(self):
        super().setUp()
        self.add_finding(file_path='app/a.py')
        self.add_finding(file_path='app/b.py')
        self.add_finding(rule=self.debug_rule, file_path='app/c.py')
        self.unmapped = self.add_finding(
            rule=None, rule_code='KISA-ZZ-99', file_path='app/d.py',
        )

    def results(self, response):
        return response.data['results']

    def test_member_sees_findings_of_assigned_project(self):
        self.login(self.member)
        response = self.client.get(findings_url(self.run.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 4)

    def test_high_severity_comes_first(self):
        """CharField 사전순이면 HIGH < LOW < MEDIUM이라 위험한 항목이 묻힌다."""
        self.login(self.member)
        severities = [row['severity']
                      for row in self.results(self.client.get(findings_url(self.run.pk)))]
        self.assertEqual(severities, ['HIGH', 'HIGH', 'MEDIUM', 'MEDIUM'])

    def test_filters_by_severity(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(findings_url(self.run.pk), {'severity': 'HIGH'}).data['count'], 2)

    def test_filters_by_category(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(findings_url(self.run.pk), {'category': 'EN'}).data['count'], 1)

    def test_filters_by_rule_code_including_unmapped(self):
        """매핑에 실패한 결과도 자기가 주장한 코드로 검색되어야 한다."""
        self.login(self.member)
        response = self.client.get(findings_url(self.run.pk), {'rule': 'KISA-ZZ-99'})
        self.assertEqual(response.data['count'], 1)
        self.assertEqual(self.results(response)[0]['id'], self.unmapped.pk)

    def test_keyword_search_matches_file_path(self):
        self.login(self.member)
        self.assertEqual(
            self.client.get(findings_url(self.run.pk), {'q': 'app/a.py'}).data['count'], 1)

    def test_unmapped_finding_serializes_without_category(self):
        self.login(self.member)
        rows = {row['id']: row
                for row in self.results(self.client.get(findings_url(self.run.pk)))}
        self.assertEqual(rows[self.unmapped.pk]['category'], '')
        self.assertEqual(rows[self.unmapped.pk]['category_label'], '')

    def test_summary_includes_zero_count_severities(self):
        """화면이 키 부재와 0건을 구분하지 않아도 되게 한다."""
        self.login(self.member)
        data = self.client.get(findings_summary_url(self.run.pk)).data
        counts = {row['severity']: row['total'] for row in data['by_severity']}
        self.assertEqual(counts, {'HIGH': 2, 'MEDIUM': 2, 'LOW': 0})
        self.assertEqual(data['total'], 4)

    def test_summary_groups_by_rule(self):
        self.login(self.member)
        data = self.client.get(findings_summary_url(self.run.pk)).data
        by_code = {row['rule_code']: row['total'] for row in data['by_rule']}
        self.assertEqual(by_code, {'KISA-IV-01': 2, 'KISA-EN-02': 1, 'KISA-ZZ-99': 1})


class IdorDefenseTests(CatalogApiTestCase):
    """SEC-005, SEC-006 — run id 조작으로 남의 결과에 닿을 수 없다."""

    def setUp(self):
        super().setUp()
        self.add_finding()
        self.add_finding(run=self.other_run)

    def test_outsider_cannot_list_findings_of_unassigned_project(self):
        self.login(self.outsider)
        self.assertEqual(self.client.get(findings_url(self.run.pk)).status_code,
                         status.HTTP_404_NOT_FOUND)

    def test_unassigned_and_missing_runs_are_indistinguishable(self):
        self.login(self.outsider)
        unassigned = self.client.get(findings_url(self.run.pk))
        missing = self.client.get(findings_url(self.missing_run_id))
        self.assertEqual(unassigned.status_code, missing.status_code)
        self.assertEqual(unassigned.json(), missing.json())

    def test_summary_is_scoped_too(self):
        self.login(self.outsider)
        self.assertEqual(self.client.get(findings_summary_url(self.run.pk)).status_code,
                         status.HTTP_404_NOT_FOUND)

    def test_scope_check_runs_before_filter_validation(self):
        """잘못된 필터로 400을 받아내 실행의 존재를 떠볼 수 없어야 한다 (SEC-006)."""
        self.login(self.outsider)
        response = self.client.get(findings_url(self.run.pk), {'severity': 'XX'})
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_member_cannot_reach_other_project(self):
        self.login(self.member)
        self.assertEqual(self.client.get(findings_url(self.other_run.pk)).status_code,
                         status.HTTP_404_NOT_FOUND)

    def test_admin_sees_every_run(self):
        self.login(self.admin)
        self.assertEqual(self.client.get(findings_url(self.other_run.pk)).status_code,
                         status.HTTP_200_OK)

    def test_revoking_assignment_blocks_immediately(self):
        self.login(self.member)
        self.assertEqual(self.client.get(findings_url(self.run.pk)).status_code,
                         status.HTTP_200_OK)

        ProjectMember.objects.filter(project=self.project, user=self.member).delete()
        self.assertEqual(self.client.get(findings_url(self.run.pk)).status_code,
                         status.HTTP_404_NOT_FOUND)

    def test_catalog_stays_readable_after_revocation(self):
        """카탈로그는 프로젝트 권한과 무관한 공통 기준 문서다."""
        ProjectMember.objects.filter(project=self.project, user=self.member).delete()
        self.login(self.member)
        self.assertEqual(self.client.get(rule_list_url()).status_code, status.HTTP_200_OK)

    def test_response_body_has_no_internal_paths(self):
        self.login(self.member)
        body = self.client.get(findings_url(self.run.pk)).content.decode('utf-8')
        self.assertNotIn(str(settings.ANALYSIS_WORKSPACE_ROOT), body)
        self.assertNotIn(str(self.run.workspace_id), body)


class ReingestTests(CatalogApiTestCase):
    """재표준화 (SFR-014, SEC-003/004)."""

    def test_regular_user_is_denied(self):
        self.login(self.member)
        self.assertEqual(self.client.post(reingest_url(self.run.pk)).status_code,
                         status.HTTP_403_FORBIDDEN)

    def test_denial_is_uniform_regardless_of_run(self):
        """쓰기 권한 검사가 객체 조회보다 먼저라 id로 존재를 떠볼 수 없다 (SEC-006)."""
        self.login(self.outsider)
        self.assertEqual(self.client.post(reingest_url(self.run.pk)).status_code,
                         status.HTTP_403_FORBIDDEN)
        self.assertEqual(self.client.post(reingest_url(self.missing_run_id)).status_code,
                         status.HTTP_403_FORBIDDEN)

    def test_admin_can_reingest(self):
        self.login(self.admin)
        response = self.client.post(reingest_url(self.run.pk))
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['created'], 0)

    def test_conflict_when_no_raw_result(self):
        run = self.make_run(self.project, self.admin, status_value=AnalysisStatus.PENDING)
        self.login(self.admin)
        self.assertEqual(self.client.post(reingest_url(run.pk)).status_code,
                         status.HTTP_409_CONFLICT)

    def test_reingest_replaces_stale_findings(self):
        self.add_finding()
        self.add_finding()
        self.login(self.admin)
        self.client.post(reingest_url(self.run.pk))
        self.assertEqual(Finding.objects.filter(run=self.run).count(), 0)


class PaginationTests(CatalogApiTestCase):
    """결과 목록에만 상한을 둔다 — 다른 앱 응답 형태는 그대로."""

    def setUp(self):
        super().setUp()
        Finding.objects.bulk_create([
            Finding(run=self.run, rule=self.sql_rule, rule_code=self.sql_rule.code,
                    rule_name=self.sql_rule.name, severity=Severity.HIGH,
                    semgrep_check_id='k', file_path=f'app/f{i}.py',
                    start_line=1, end_line=1, message='m', extra={})
            for i in range(FindingPagination.max_page_size + 60)
        ])

    def test_default_page_size(self):
        self.login(self.member)
        response = self.client.get(findings_url(self.run.pk))
        self.assertEqual(len(response.data['results']), FindingPagination.page_size)
        self.assertEqual(response.data['count'], FindingPagination.max_page_size + 60)

    def test_page_size_is_capped(self):
        self.login(self.member)
        response = self.client.get(findings_url(self.run.pk), {'page_size': 9999})
        self.assertEqual(len(response.data['results']), FindingPagination.max_page_size)

    def test_catalog_list_is_not_paginated(self):
        """전역 설정이 아니라 이 뷰에만 걸었다는 확인."""
        self.login(self.member)
        self.assertIsInstance(self.client.get(rule_list_url()).data, list)

    def test_summary_is_not_paginated(self):
        self.login(self.member)
        self.assertIn('by_severity', self.client.get(findings_summary_url(self.run.pk)).data)


# ---------------------------------------------------------------------------
# 앱 연결 (QLT-001)
# ---------------------------------------------------------------------------

class SignalWiringTests(WorkspaceMixin, TestCase):
    """실행 성공 → 표준화 자동 연결. analysis는 catalog를 모른다."""

    def setUp(self):
        super().setUp()
        seed()
        self.setup_workspace()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.project = Project.objects.create(name='p', created_by=self.admin)

    def make_running_run(self):
        run = self.make_run(self.project, self.admin, status_value=AnalysisStatus.RUNNING)
        self.write_source(run, 'app.py', 'import pickle\npickle.loads(b"")\n')
        return run

    def semgrep_stdout(self, run):
        return json.dumps({
            'results': [semgrep_result(source_dir(run) / 'app.py', 'KISA-CE-05', line=2)],
            'errors': [],
        })

    def test_receiver_is_connected(self):
        receivers = run_succeeded._live_receivers(AnalysisRun)
        receivers = receivers[0] if isinstance(receivers, tuple) else receivers
        names = [f'{r.__module__}.{r.__name__}' for r in receivers]
        self.assertEqual(names, ['catalog.receivers.ingest_on_run_succeeded'])

    def test_successful_run_creates_findings(self):
        run = self.make_running_run()
        with patch('analysis.services.subprocess.run') as mocked:
            mocked.return_value = subprocess.CompletedProcess(
                args=[], returncode=0, stdout=self.semgrep_stdout(run), stderr='')
            run_semgrep(run)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertEqual(Finding.objects.filter(run=run).count(), 1)

    def test_failed_run_creates_no_findings(self):
        run = self.make_running_run()
        with patch('analysis.services.subprocess.run') as mocked:
            mocked.return_value = subprocess.CompletedProcess(
                args=[], returncode=2, stdout='', stderr='config error')
            run_semgrep(run)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.FAILED)
        self.assertEqual(Finding.objects.filter(run=run).count(), 0)

    def test_ingest_failure_does_not_break_the_run(self):
        """표준화 예외를 올리면 실행은 SUCCEEDED인데 요청은 500이 되어 복구 경로가 없다."""
        run = self.make_running_run()
        with patch('catalog.receivers.ingest_findings', side_effect=RuntimeError('boom')):
            with patch('analysis.services.subprocess.run') as mocked:
                mocked.return_value = subprocess.CompletedProcess(
                    args=[], returncode=0, stdout=self.semgrep_stdout(run), stderr='')
                with self.assertLogs('catalog.receivers', level='ERROR'):
                    run_semgrep(run)

        run.refresh_from_db()
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED)
        self.assertIsNotNone(run.raw_result)

    def test_analysis_app_does_not_import_catalog(self):
        """의존이 catalog→analysis 한 방향으로 유지되는지 소스로 확인한다 (QLT-001)."""
        pattern = re.compile(r'^\s*(from|import)\s+catalog', re.MULTILINE)
        for path in (Path(settings.BASE_DIR) / 'analysis').glob('*.py'):
            self.assertIsNone(pattern.search(path.read_text(encoding='utf-8')), path.name)


# ---------------------------------------------------------------------------
# 정탐·오탐 (TST-005)
# ---------------------------------------------------------------------------

@unittest.skipUnless(SEMGREP_AVAILABLE, 'semgrep 바이너리가 없어 건너뜀')
@override_settings(ANALYSIS_SEMGREP_CONFIG=str(settings.CATALOG_RULES_DIR))
class DetectionSampleTests(WorkspaceMixin, TestCase):
    """실제 Semgrep으로 취약·안전 샘플을 분석한다 (TST-005).

    바이너리가 없는 환경에서는 건너뛴다 — 나머지 시험은 모킹으로 돌기 때문에
    스위트 전체가 막히지 않는다.
    """

    def setUp(self):
        super().setUp()
        seed()
        self.setup_workspace()
        self.admin = User.objects.create_user(
            email='admin@example.com', password=PASSWORD, role=Role.ADMIN,
        )
        self.project = Project.objects.create(name='p', created_by=self.admin)

    def analyze(self, *sample_names):
        run = self.make_run(self.project, self.admin, status_value=AnalysisStatus.RUNNING)
        for name in sample_names:
            self.write_source(run, f'src/{name}',
                              (SAMPLES_DIR / name).read_text(encoding='utf-8'))
        run_semgrep(run)
        run.refresh_from_db()
        return run

    def test_vulnerable_sample_triggers_every_rule(self):
        run = self.analyze('vulnerable.py')
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED, run.error_message)

        counts = {}
        for finding in Finding.objects.filter(run=run):
            counts[finding.rule_code] = counts.get(finding.rule_code, 0) + 1
        self.assertEqual(counts, EXPECTED_SAMPLE_FINDINGS)

    def test_safe_sample_produces_no_findings(self):
        """오탐 통제 — 안전한 대응 코드에서 하나라도 나오면 룰이 과탐지하는 것이다."""
        run = self.analyze('safe.py')
        self.assertEqual(run.status, AnalysisStatus.SUCCEEDED, run.error_message)
        self.assertEqual(
            list(Finding.objects.filter(run=run).values_list('file_path', 'rule_code')), [])

    def test_catalog_severity_overrides_tool_severity(self):
        """도구 등급과 카탈로그 등급이 실제로 충돌하는 두 항목으로 확인한다 (QLT-004)."""
        run = self.analyze('vulnerable.py')

        lowered = Finding.objects.filter(run=run, rule_code='KISA-EH-01')
        raised = Finding.objects.filter(run=run, rule_code='KISA-SF-08')
        self.assertTrue(lowered.exists() and raised.exists())
        # 등급이 내려가는 방향
        self.assertTrue(all(f.extra['semgrep_severity'] == 'ERROR' for f in lowered))
        self.assertTrue(all(f.severity == Severity.MEDIUM for f in lowered))
        # 등급이 올라가는 방향
        self.assertTrue(all(f.extra['semgrep_severity'] == 'WARNING' for f in raised))
        self.assertTrue(all(f.severity == Severity.HIGH for f in raised))

    def test_workspace_is_scanned_despite_gitignore(self):
        """작업 영역은 .gitignore의 /media/ 아래라 --no-git-ignore가 없으면 0건이 된다."""
        run = self.analyze('vulnerable.py')
        self.assertTrue((run.raw_result or {}).get('paths', {}).get('scanned'))

    def test_korean_rule_messages_survive_encoding(self):
        """룰 파일·출력 인코딩을 명시하지 않으면 한글에서 깨진다."""
        run = self.analyze('vulnerable.py')
        messages = [f.message for f in Finding.objects.filter(run=run)]
        self.assertTrue(any('삽입' in message for message in messages), messages[:3])


# ---------------------------------------------------------------------------
# 문서 동기화
# ---------------------------------------------------------------------------

class SeedDocumentationTests(SimpleTestCase):
    """시드 데이터의 등급 근거가 결정 기록과 어긋나지 않는지 (QLT-004).

    같은 문장을 두 곳에 두기로 한 만큼(데이터는 화면 표시용, 문서는 근거 기록)
    드리프트가 실제 위험이다.
    """

    def setUp(self):
        super().setUp()
        self.seed = json.loads(Path(settings.CATALOG_SEED_FILE).read_text(encoding='utf-8'))
        doc = (Path(settings.BASE_DIR) / 'docs' / 'decisions.md').read_text(encoding='utf-8')
        self.doc = re.sub(r'\s+', ' ', doc)

    def test_declared_total_matches_rule_count(self):
        self.assertEqual(self.seed['total'], len(self.seed['rules']))

    def test_implemented_rules_have_severity_reason(self):
        for rule in self.seed['rules']:
            if rule['code'] in IMPLEMENTED_CODES:
                self.assertTrue(rule['severity_reason'].strip(), rule['code'])

    def test_severity_reasons_are_recorded_in_decisions(self):
        for rule in self.seed['rules']:
            reason = rule['severity_reason'].strip()
            if not reason:
                continue
            self.assertIn(re.sub(r'\s+', ' ', reason), self.doc, rule['code'])
