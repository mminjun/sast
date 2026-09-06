"""프로젝트별 분석 제외 경로 — 검증과 매칭 (SEC-008, RFP 외 자체 개선).

CI 워크플로(.github/workflows/sast-scan.yml)가 `--exclude`로 샘플·픽스처를 빼는 것과
같은 개념을 서버 프로젝트에도 둔다. 값은 그대로 Semgrep `--exclude=<값>` 인자가 되므로
여기서 한 번 걸러 이상한 값이 인자로 넘어가지 않게 한다. subprocess는 shell=False라
셸 인젝션은 애초에 불가능하지만, 인자 값 자체(`..`, 절대 경로, 제어 문자)는 별개다.

Semgrep 1.175.0 `--exclude` 동작(2026-09-05 실험, docs/decisions.md):
- `/`가 있으면 대상 루트에 앵커된 경로 — `catalog/samples`는 `sub/catalog/samples`를
  제외하지 않는다.
- `/`가 없으면 어느 깊이든 그 이름의 파일·디렉토리 — `tests.py`는 `pkg/tests.py`도 제외.
- 글롭(`*`, `?`) 사용 가능. 앞뒤 `/`는 있으나 없으나 같다.

`is_excluded`는 이 규칙을 그대로 따른다 — 실행 전 "분석 대상 파일이 0개인가" 검사가
Semgrep과 다른 판단을 하면 Semgrep이 0건으로 SUCCEEDED 하는 상황이 다시 생긴다.
"""

import fnmatch
import re

from django.core.exceptions import ValidationError

MAX_ENTRIES = 50
MAX_ENTRY_LENGTH = 200

# 허용 문자: 유니코드 단어 문자(한글 디렉토리 이름 포함)·점·하이픈·글롭 `*` `?`·구분자 `/`·공백.
# 그 밖(역슬래시, 드라이브 `:`, 따옴표, `!`(semgrepignore 부정), `[`, 셸 메타 등)은 거부.
# fullmatch로 검사한다 — `$`는 끝의 줄바꿈 앞에서도 매칭돼 끝에 줄바꿈이 붙은 값을 통과시킨다.
_ALLOWED = re.compile(r'[\w.\-*?/ ]+')


def normalize_exclude_path(value):
    """항목 하나를 검증하고 정규화한다. 잘못되면 ValueError(사용자용 메시지).

    정규화: 앞뒤 공백·`/` 제거. 앞뒤 `/`는 Semgrep에 의미가 없으므로 저장 형태를 하나로
    맞춘다(`catalog/samples/`와 `catalog/samples`가 다른 값으로 저장되지 않게).
    """
    if not isinstance(value, str):
        raise ValueError('문자열이어야 합니다.')
    path = value.strip()
    if not path:
        raise ValueError('빈 항목은 넣을 수 없습니다.')
    if len(path) > MAX_ENTRY_LENGTH:
        raise ValueError(f'{MAX_ENTRY_LENGTH}자를 넘을 수 없습니다.')
    if '\\' in path:
        raise ValueError('경로 구분자는 / 를 쓰세요.')
    if not _ALLOWED.fullmatch(path):
        raise ValueError('사용할 수 없는 문자가 있습니다 (영문·숫자·한글·. - _ * ? / 만 가능).')
    if path.startswith('-'):
        # `--exclude=-x` 형태라 옵션으로 오해될 일은 없지만, 인자 값이 대시로 시작하는 것
        # 자체를 허용하지 않는다 — 명령줄 인자로 넘기는 값의 보수적 기본값.
        raise ValueError('- 로 시작할 수 없습니다.')

    path = path.strip('/')
    if not path:
        raise ValueError('루트 전체를 제외할 수 없습니다.')
    parts = path.split('/')
    if any(part == '' for part in parts):
        raise ValueError('빈 경로 조각(//)이 있습니다.')
    if any(part == '..' for part in parts):
        raise ValueError('상위 디렉토리(..)는 쓸 수 없습니다.')
    if any(part == '.' for part in parts):
        raise ValueError('현재 디렉토리(.)는 쓸 수 없습니다.')
    if any(part.strip() != part for part in parts):
        raise ValueError('경로 조각 앞뒤에 공백이 있습니다.')
    return path


def validate_exclude_paths(values):
    """목록 전체를 검증해 정규화·중복 제거한 list를 돌려준다. 잘못되면 ValueError."""
    if values is None:
        return []
    if not isinstance(values, (list, tuple)):
        raise ValueError('경로 목록(배열)이어야 합니다.')
    if len(values) > MAX_ENTRIES:
        raise ValueError(f'제외 경로는 최대 {MAX_ENTRIES}개까지 등록할 수 있습니다.')

    cleaned = []
    for index, value in enumerate(values, start=1):
        try:
            path = normalize_exclude_path(value)
        except ValueError as exc:
            raise ValueError(f'{index}번째 항목 "{value}": {exc}') from None
        if path not in cleaned:
            cleaned.append(path)
    return cleaned


def is_excluded(rel_parts, patterns):
    """소스 루트 기준 상대 경로 조각(rel_parts)이 제외 패턴 중 하나에 걸리는가.

    Semgrep과 같은 규칙: `/`가 든 패턴은 루트에 앵커된 접두 경로(조각별 글롭),
    `/`가 없는 패턴은 어느 깊이의 파일·디렉토리 이름이든 글롭 매칭.
    patterns는 normalize_exclude_path를 거친 값이어야 한다.
    """
    parts = list(rel_parts)
    for pattern in patterns:
        if '/' in pattern:
            pattern_parts = pattern.split('/')
            if len(pattern_parts) <= len(parts) and all(
                fnmatch.fnmatchcase(part, pat)
                for part, pat in zip(parts, pattern_parts)
            ):
                return True
        elif any(fnmatch.fnmatchcase(part, pattern) for part in parts):
            return True
    return False


def validate_exclude_paths_field(value):
    """모델 필드 validator — DRF를 거치지 않는 경로(Django admin 폼 등)에서도 같은 규칙.

    full_clean()에서만 돌고 save()에서는 돌지 않으므로, 실행 직전(analysis.services)에
    한 번 더 검증해 저장된 값이 어떤 경로로 들어왔든 검증 없이 인자가 되지 않게 한다.
    """
    try:
        validate_exclude_paths(value)
    except ValueError as exc:
        raise ValidationError(str(exc)) from None
