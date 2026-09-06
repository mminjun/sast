"""엔진 진입점 — 디렉토리(격리된 소스)를 돌며 Python 파일을 분석한다 (docs/decisions.md 2026-09-06 custom-taint).

best-effort다: 파일 하나의 문법 오류·읽기 실패·예외는 errors에 한 줄로 남기고 다음 파일로 간다. 시간 예산을
넘기면 남은 파일을 건너뛰고 stats에 적는다. 결과는 {'results': [Semgrep 모양 item], 'errors': [...],
'stats': {...}} — 호출자(analysis/services.run_custom_taint)가 AnalysisRun.custom_result에 그대로 저장한다.
"""

import os
import time
from pathlib import Path

from .python_analyzer import analyze_module
from .report import to_item

DEFAULT_SUFFIXES = ('.py',)
DEFAULT_MAX_FILE_BYTES = 1024 * 1024
# Windows 확장 경로 접두사 — 260자 넘는 경로를 읽기 위해 (analysis.services.fs_path와 같은 규칙, Django 없이).
_EXTENDED_PREFIX = '\\\\?\\'


def _read_path(path):
    text = os.fspath(path)
    if os.name == 'nt' and not text.startswith(_EXTENDED_PREFIX):
        return _EXTENDED_PREFIX + os.path.abspath(text)
    return text


def analyze_source(source, rel_path='<source>'):
    """소스 텍스트 하나 → Finding 목록 (시험·CI용). SyntaxError는 그대로 올린다."""
    return analyze_module(source, rel_path)


def analyze_directory(source_root, *, time_budget=120.0, max_file_bytes=DEFAULT_MAX_FILE_BYTES,
                      suffixes=DEFAULT_SUFFIXES, is_excluded=None):
    """source_root 아래 파일을 분석한다.

    is_excluded(rel_parts) → bool: 프로젝트의 분석 제외 경로 판정(projects.exclude_paths.is_excluded와 같은 규칙,
    Django 의존을 피하려 호출자가 넘긴다). None이면 제외 없음.
    """
    root = Path(source_root)
    started = time.perf_counter()
    results, errors = [], []
    stats = {
        'files': 0, 'analyzed': 0, 'findings': 0,
        'skipped_excluded': 0, 'skipped_size': 0, 'skipped_budget': 0, 'parse_errors': 0,
        'summary_passes': 0,  # 함수 요약 고정점 반복 횟수의 최대(파일 기준) — 상한에 닿았는지 보는 용도
        'seconds': 0.0,
    }

    for path in sorted(p for p in root.rglob('*') if p.suffix.lower() in suffixes):
        rel_parts = path.relative_to(root).parts
        rel_path = '/'.join(rel_parts)
        stats['files'] += 1
        if is_excluded is not None and is_excluded(rel_parts):
            stats['skipped_excluded'] += 1
            continue
        if time.perf_counter() - started > time_budget:
            stats['skipped_budget'] += 1
            continue
        try:
            if path.stat().st_size > max_file_bytes:
                stats['skipped_size'] += 1
                continue
            source = Path(_read_path(path)).read_text(encoding='utf-8', errors='replace')
            findings = analyze_module(source, rel_path, stats)
        except SyntaxError as exc:
            stats['parse_errors'] += 1
            errors.append(f'{rel_path}: 문법 오류 (line {exc.lineno}): {exc.msg}')
            continue
        except Exception as exc:  # noqa: BLE001 — 한 파일의 실패가 실행 전체를 막지 않는다
            errors.append(f'{rel_path}: {type(exc).__name__}: {exc}'[:500])
            continue
        stats['analyzed'] += 1
        stats['findings'] += len(findings)
        results.extend(to_item(f, str(path)) for f in findings)

    if stats['skipped_budget']:
        errors.append(f'시간 예산 {time_budget:.0f}초 초과 — {stats["skipped_budget"]}개 파일을 건너뛰었습니다.')
    stats['seconds'] = round(time.perf_counter() - started, 3)
    return {'results': results, 'errors': errors, 'stats': stats}
