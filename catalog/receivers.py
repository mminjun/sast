"""분석 실행 완료 → 결과 표준화 연결 (SFR-014, QLT-001).

analysis 앱은 run_succeeded 시그널만 발신하고 누가 듣는지 모른다. 연결은 이쪽에서만
안다 — 의존이 catalog→analysis 한 방향으로 유지된다 (docs/decisions.md).
"""

import logging

from django.dispatch import receiver

from analysis.models import AnalysisRun
from analysis.signals import run_succeeded

from .services import ingest_findings

logger = logging.getLogger(__name__)


@receiver(run_succeeded, sender=AnalysisRun, dispatch_uid='catalog.ingest_on_run_succeeded')
def ingest_on_run_succeeded(sender, run, **kwargs):
    """분석이 성공하면 원본 결과를 표준화해 Finding으로 저장한다.

    표준화 실패를 호출자(분석 실행 API)로 올리지 않는다. 분석 자체는 이미 끝났고
    raw_result도 저장돼 있어 되돌릴 수 없는데, 여기서 예외를 올리면 실행 요청이 500이
    되면서 run은 SUCCEEDED로 남는다 — 재실행은 409로 막히고 복구 경로가 사라진다.
    대신 traceback을 남기고, 관리자가 재표준화 API로 다시 시도할 수 있게 한다.

    삼키는 대신 반드시 로그로 드러낸다 — 결과가 0건인데 아무 흔적도 없는 상태가
    가장 위험하다(docs/decisions.md의 '파이프라인이 도는가 vs 결과가 나오는가').
    """
    try:
        result = ingest_findings(run)
    except Exception:
        logger.exception(
            '분석 결과 표준화 실패 (run=%s). raw_result는 보존돼 있으므로 '
            '재표준화 API로 다시 시도할 수 있습니다.',
            run.pk,
        )
        return

    logger.info(
        '분석 결과 표준화 완료 (run=%s): 저장 %d건, 격리 밖 경로로 제외 %d건, 미매핑 %d건',
        run.pk, result.created, result.skipped, result.unmapped,
    )
