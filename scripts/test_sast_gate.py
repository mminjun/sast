"""CI 게이트 스크립트(scripts/sast_gate.py) 테스트 — Django 없이 도는 순수 unittest.

manage.py test가 test*.py 패턴으로 발견해 함께 돈다. 핵심은 "신규"의 정의가 서버의
diff와 같은가 — 핑거프린트·조각 읽기를 같은 모듈에서 가져오므로 여기서는 게이트
판정·분류·렌더링을 검증한다 (RFP 외 자체 개선, docs/decisions.md 2026-09-04).
"""

import contextlib
import io
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from scripts import sast_gate

LF = chr(10)


def result(path, kisa_code, line, severity='ERROR', message='m', end_line=None):
    return {
        'check_id': f'catalog.rules.{kisa_code.lower()}-rule',
        'path': path,
        'start': {'line': line},
        'end': {'line': end_line or line},
        'extra': {
            'severity': severity,
            'message': message,
            'lines': 'requires login',
            'metadata': {'kisa_code': kisa_code},
        },
    }


class GateTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix='sast-gate-'))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)
        self.head_root = self.tmp / 'head'
        self.base_root = self.tmp / 'base'
        self.catalog = sast_gate.load_catalog()

    def write(self, root, relative_path, content):
        target = root / relative_path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(content, encoding='utf-8')

    def findings(self, root, results):
        return sast_gate.load_findings(results, root, self.catalog)

    def run_main(self, head_results, base_results=None, **extra):
        head_json = self.tmp / 'head.json'
        head_json.write_text(json.dumps({'results': head_results}), encoding='utf-8')
        argv = ['--head', str(head_json), '--head-root', str(self.head_root)]
        if base_results is not None:
            base_json = self.tmp / 'base.json'
            base_json.write_text(json.dumps({'results': base_results}), encoding='utf-8')
            argv += ['--base', str(base_json), '--base-root', str(self.base_root)]
        for key, value in extra.items():
            argv += [f'--{key}', str(value)]
        # 스크립트는 러너 로그용으로 마크다운을 stdout에 찍는다 — 테스트 출력은 조용히.
        with contextlib.redirect_stdout(io.StringIO()):
            return sast_gate.main(argv)


class ClassifyTests(GateTestCase):
    def test_same_code_moved_lines_is_persisted(self):
        """줄 번호가 밀려도 같은 코드는 유지 — 핑거프린트에 줄 번호가 없다."""
        self.write(self.base_root, 'app/db.py', 'q = 1' + LF + 'cur.execute(f"x{q}")' + LF)
        self.write(self.head_root, 'app/db.py', LF * 5 + 'cur.execute(f"x{q}")' + LF)
        base = self.findings(self.base_root, [result('app/db.py', 'KISA-IV-01', 2)])
        head = self.findings(self.head_root, [result('app/db.py', 'KISA-IV-01', 6)])

        items = sast_gate.classify(base, head)

        self.assertEqual([(s, f.start_line) for s, f in items], [('persisted', 6)])

    def test_new_resolved_persisted(self):
        self.write(self.base_root, 'a.py', 'eval(x)' + LF + 'os.system(y)' + LF)
        self.write(self.head_root, 'a.py', 'eval(x)' + LF + 'pickle.loads(z)' + LF)
        base = self.findings(self.base_root, [
            result('a.py', 'KISA-IV-02', 1), result('a.py', 'KISA-IV-05', 2),
        ])
        head = self.findings(self.head_root, [
            result('a.py', 'KISA-IV-02', 1), result('a.py', 'KISA-IV-12', 2),
        ])

        items = sast_gate.classify(base, head)

        self.assertEqual(
            [(s, f.rule_code) for s, f in items],
            [('new', 'KISA-IV-12'), ('resolved', 'KISA-IV-05'), ('persisted', 'KISA-IV-02')],
        )

    def test_duplicate_code_is_paired_by_position(self):
        """동일 코드 2건 중 앞쪽을 고치면 남은 1건은 유지, 해결은 1건."""
        self.write(self.base_root, 'a.py', 'eval(x)' + LF + 'eval(x)' + LF)
        self.write(self.head_root, 'a.py', 'ok()' + LF + 'eval(x)' + LF)
        base = self.findings(self.base_root, [
            result('a.py', 'KISA-IV-02', 1), result('a.py', 'KISA-IV-02', 2),
        ])
        head = self.findings(self.head_root, [result('a.py', 'KISA-IV-02', 2)])

        items = sast_gate.classify(base, head)

        self.assertEqual(
            sorted((s, f.start_line) for s, f in items),
            [('persisted', 2), ('resolved', 2)],
        )

    def test_no_base_means_all_new(self):
        self.write(self.head_root, 'a.py', 'eval(x)' + LF)
        head = self.findings(self.head_root, [result('a.py', 'KISA-IV-02', 1)])
        self.assertEqual([s for s, _ in sast_gate.classify([], head)], ['new'])


class SeverityTests(GateTestCase):
    def test_catalog_severity_wins_over_semgrep(self):
        """KISA-EH-01은 룰 severity가 ERROR지만 카탈로그 등급 MEDIUM이 최종 (QLT-004)."""
        self.write(self.head_root, 'a.py', 'DEBUG = True' + LF)
        [finding] = self.findings(
            self.head_root, [result('a.py', 'KISA-EH-01', 1, severity='ERROR')],
        )
        self.assertEqual(finding.severity, 'MEDIUM')
        self.assertEqual(finding.rule_name, '오류 메시지 정보노출')

    def test_unmapped_code_falls_back_to_semgrep_then_medium(self):
        self.write(self.head_root, 'a.py', 'x' + LF)
        [warn] = self.findings(self.head_root, [result('a.py', 'KISA-ZZ-99', 1, 'WARNING')])
        [odd] = self.findings(self.head_root, [result('a.py', 'KISA-ZZ-99', 1, 'WHAT')])
        self.assertEqual(warn.severity, 'MEDIUM')
        self.assertEqual(odd.severity, 'MEDIUM')
        [err] = self.findings(self.head_root, [result('a.py', 'KISA-ZZ-99', 1, 'ERROR')])
        self.assertEqual(err.severity, 'HIGH')

    def test_check_id_prefix_is_stripped(self):
        self.write(self.head_root, 'a.py', 'x' + LF)
        [finding] = self.findings(self.head_root, [result('a.py', 'KISA-IV-01', 1)])
        self.assertEqual(finding.semgrep_check_id, 'kisa-iv-01-rule')


class GateVerdictTests(GateTestCase):
    def test_new_high_fails(self):
        self.write(self.base_root, 'a.py', 'ok()' + LF)
        self.write(self.head_root, 'a.py', 'cur.execute(f"x{q}")' + LF)
        code = self.run_main([result('a.py', 'KISA-IV-01', 1)], [])
        self.assertEqual(code, 1)

    def test_new_medium_only_passes(self):
        self.write(self.head_root, 'a.py', 'DEBUG = True' + LF)
        code = self.run_main([result('a.py', 'KISA-EH-01', 1)], [])
        self.assertEqual(code, 0)

    def test_persisted_high_passes(self):
        self.write(self.base_root, 'a.py', 'eval(x)' + LF)
        self.write(self.head_root, 'a.py', 'eval(x)' + LF)
        code = self.run_main(
            [result('a.py', 'KISA-IV-02', 1)], [result('a.py', 'KISA-IV-02', 1)],
        )
        self.assertEqual(code, 0)

    def test_writes_summary_and_comment(self):
        self.write(self.head_root, 'a.py', 'eval(x)' + LF)
        summary = self.tmp / 'summary.md'
        summary.write_text('prev' + LF, encoding='utf-8')
        comment = self.tmp / 'comment.md'

        code = self.run_main(
            [result('a.py', 'KISA-IV-02', 1)], [], summary=summary, comment=comment,
        )

        self.assertEqual(code, 1)
        text = comment.read_text(encoding='utf-8')
        self.assertTrue(text.startswith(sast_gate.COMMENT_MARKER))
        self.assertIn('차단', text)
        self.assertIn('| 신규 | 1 | 0 | 0 | 1 |', text)
        self.assertIn('`a.py:1`', text)
        self.assertIn('KISA-IV-02 코드삽입', text)
        self.assertTrue(summary.read_text(encoding='utf-8').startswith('prev' + LF))


class RenderTests(GateTestCase):
    def test_resolved_and_persisted_are_collapsed(self):
        self.write(self.base_root, 'a.py', 'eval(x)' + LF + 'os.system(y)' + LF)
        self.write(self.head_root, 'a.py', 'eval(x)' + LF)
        base = self.findings(self.base_root, [
            result('a.py', 'KISA-IV-02', 1), result('a.py', 'KISA-IV-05', 2),
        ])
        head = self.findings(self.head_root, [result('a.py', 'KISA-IV-02', 1)])

        text = sast_gate.render_markdown(sast_gate.classify(base, head))

        self.assertIn('통과', text)
        self.assertIn('### 신규 0건', text)
        self.assertIn('<summary>해결 1건</summary>', text)
        self.assertIn('<summary>유지 1건</summary>', text)

    def test_message_pipes_and_newlines_are_escaped(self):
        self.write(self.head_root, 'a.py', 'eval(x)' + LF)
        head = self.findings(self.head_root, [
            result('a.py', 'KISA-IV-02', 1, message='a | b' + LF + 'c'),
        ])
        text = sast_gate.render_markdown(sast_gate.classify([], head))
        self.assertIn('a \\| b c', text)


if __name__ == '__main__':
    unittest.main()
