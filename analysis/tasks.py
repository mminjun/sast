"""분석 실행 백그라운드 작업 (SFR-008~009, SFR-015, SEC-009).

실행 요청(뷰)은 run을 QUEUED로 바꾸고 이 작업을 큐에 넣기만 한다. 실제 Semgrep 실행은
워커 프로세스(manage.py analysis_worker)가 이 작업을 집어 가서 한다. 큐 백엔드는
settings.TASKS로 정한다 — database(워커 필요) 또는 immediate(요청 안에서 동기, 테스트).

Celery 등 다른 큐로 옮길 때도 이 파일과 뷰는 그대로다 — 바꾸는 것은 settings.TASKS의
BACKEND와 워커 기동 명령뿐이다 (docs/decisions.md 2026-09-06 "확장 경로").
"""

import logging

from django.tasks import task
from django.utils import timezone

from .models import AnalysisRun, AnalysisStatus
from .services import run_semgrep, start_run

logger = logging.getLogger(__name__)


@task
def run_analysis(run_id):
    """QUEUED 상태의 run 하나를 실행한다. 인자는 run의 pk 하나뿐(JSON 직렬화 가능해야 한다).

    같은 작업이 두 번 전달돼도 안전하다: start_run의 조건부 UPDATE(QUEUED→RUNNING)가
    0행이면 다른 워커가 이미 집어 갔거나 상태가 바뀐 것이므로 아무것도 하지 않는다
    (analysis/services.py start_run 참고). run이 지워졌어도 마찬가지로 조용히 끝낸다.
    """
    run = AnalysisRun.objects.select_related('project').filter(pk=run_id).first()
    if run is None:
        logger.warning('분석 작업 건너뜀 — run=%s 없음 (등록 뒤 삭제됨)', run_id)
        return
    if not start_run(run):
        logger.info('분석 작업 건너뜀 — run=%s 상태 %s (중복 전달 또는 상태 변경)', run_id, run.status)
        return

    try:
        run_semgrep(run)
    except Exception as exc:
        # run_semgrep은 예상한 실패(타임아웃·exit≠0·대상 없음)를 스스로 FAILED로 기록한다.
        # 여기 오는 것은 예상 밖 예외(JSON 파싱, 파일시스템 등)다 — RUNNING에 고착되지 않게
        # FAILED로 남기고, 큐 쪽 작업 행에도 traceback이 기록되도록 다시 올린다.
        AnalysisRun.objects.filter(pk=run.pk, status=AnalysisStatus.RUNNING).update(
            status=AnalysisStatus.FAILED,
            error_message=f'분석 실행 중 예상하지 못한 오류: {type(exc).__name__}: {exc}'[:4000],
            finished_at=timezone.now(),
        )
        raise
