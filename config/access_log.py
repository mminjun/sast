"""결과 열람 접근 로그 (RFP 요구 아님 — 자체 개선, docs/decisions.md 2026-09-01).

"누가 어떤 결과를 언제 열람했는가"를 남긴다. settings.LOGGING의 'access' 로거가
logs/access.log로 기록하고, 시각은 formatter의 asctime이 붙인다.
이후 diff 조회 같은 열람 API가 추가되면 같은 함수를 호출한다.
"""

import logging

logger = logging.getLogger('access')


def log_access(user, action, *, run_id=None, project_id=None):
    """열람 이력을 INFO로 남긴다.

    로깅은 부가 기능이다 — 어떤 실패도 조회 요청을 막아서는 안 되므로
    예외를 전부 흡수한다 (파일 핸들러 오류는 logging 모듈도 삼킨다).
    """
    try:
        logger.info(
            'user=%s action=%s run=%s project=%s',
            getattr(user, 'email', '-'), action, run_id, project_id,
        )
    except Exception:
        pass
