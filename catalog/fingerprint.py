"""Finding 핑거프린트 계산 (실행 간 diff의 매칭 키 — RFP 외 자체 개선).

두 실행(run)의 결과를 짝지으려면 "같은 취약점"을 식별하는 안정적인 키가 필요하다.
규칙은 이 모듈 한 곳에만 둔다 — ingest(catalog/services.py)와 마이그레이션 백필이
같은 함수를 쓰지 않으면 기존 run과 새 run의 키가 어긋나 diff가 전부 틀어진다.
규칙을 변경하면 과거 데이터 재백필이 필요하다 (docs/decisions.md 2026-09-02).

키 구성 (docs/decisions.md 2026-09-02):
  - sha256("{rule_code 또는 semgrep_check_id}|{file_path}|{공백 정규화한 code_snippet}") hex
  - 라인 번호는 넣지 않는다 — 코드 한 줄만 밀려도 전부 신규/해결로 잡히기 때문.
  - 같은 run 안의 동일 해시에는 start_line 오름차순으로 ":1", ":2" 순번을 붙인다.
    중복이 1건뿐이어도 항상 ":1"을 붙인다 — "둘 이상일 때만" 방식은 중복이 2→1로
    줄어드는 순간 생존자의 키가 바뀌어(무접미사≠":1") diff 건수가 틀어진다.

이 모듈은 모델을 import하지 않는다 — 마이그레이션에서 import해도 앱 로딩 순서나
모델 변경의 영향을 받지 않게 하기 위해서다.
"""

import hashlib
import re


def normalize_snippet(text):
    """코드 조각의 공백을 정규화한다 — 연속 공백(개행 포함)→1개, 앞뒤 트림.

    들여쓰기·줄바꿈 정리 같은 순수 포매팅 변경으로 취약점이 신규로 잡히지 않게 한다.
    """
    return re.sub(r'\s+', ' ', text or '').strip()


def base_fingerprint(rule_code, semgrep_check_id, file_path, code_snippet):
    """순번을 붙이기 전의 기본 해시(64자 hex).

    룰 식별자는 rule_code, 없으면 semgrep_check_id — Finding.__str__과 같은 폴백이다.
    미매핑이라도 주장된 kisa_code(rule_code)가 있으면 그걸 쓰므로, 나중에 매핑이
    생겨도 키가 바뀌지 않는다.
    """
    key = '|'.join((
        rule_code or semgrep_check_id or '',
        file_path or '',
        normalize_snippet(code_snippet),
    ))
    return hashlib.sha256(key.encode('utf-8')).hexdigest()


def assign_fingerprints(findings):
    """finding들(한 run 분량)에 fingerprint를 계산해 세팅한다. 저장은 호출자 몫.

    순번 부여가 결정적이도록 정렬 키를 (start_line, end_line, message)로 고정한다 —
    데이터에서만 나오는 키라 ingest(미저장 인스턴스)와 백필(저장된 행) 어느 경로로
    계산해도 같은 순번이 나온다. raw_result 순서나 id처럼 경로마다 달라지는 기준을
    쓰면 start_line 동률에서 두 경로의 순번이 어긋난다.
    """
    ordered = sorted(
        findings,
        key=lambda f: (f.start_line, f.end_line, f.message),
    )
    counts = {}
    for finding in ordered:
        base = base_fingerprint(
            finding.rule_code,
            finding.semgrep_check_id,
            finding.file_path,
            finding.code_snippet,
        )
        counts[base] = counts.get(base, 0) + 1
        finding.fingerprint = f'{base}:{counts[base]}'


def backfill_fingerprints(finding_model, batch_size=500):
    """기존 finding 전체의 fingerprint를 run 단위로 다시 계산해 저장한다.

    마이그레이션 백필용 — 모델 클래스를 인자로 받으므로 마이그레이션의 historical
    model(apps.get_model)과 실제 모델 어느 쪽으로도 부를 수 있고, 테스트도 같은
    함수를 검증한다. DB에 저장된 값만 사용한다 — 격리 디렉토리는 실행이 끝나면
    정리되므로 파일시스템에는 접근하지 않는다.
    """
    run_ids = (
        finding_model.objects.values_list('run_id', flat=True).distinct()
    )
    for run_id in run_ids:
        findings = list(finding_model.objects.filter(run_id=run_id))
        assign_fingerprints(findings)
        finding_model.objects.bulk_update(
            findings, ['fingerprint'], batch_size=batch_size,
        )
