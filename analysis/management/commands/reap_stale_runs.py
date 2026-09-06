"""고착된 RUNNING 실행 정리 — 수동용 (SEC-009).

워커 시작(analysis_worker)이 같은 함수를 자동으로 부르므로 평소엔 쓸 일이 없다.
워커를 띄우지 않고 상태만 정리하고 싶을 때 쓴다. 판정 기준은
analysis/services.py stale_run_threshold (Semgrep 타임아웃 + ANALYSIS_STALE_RUN_GRACE).

사용:
    python manage.py reap_stale_runs
"""

from django.core.management.base import BaseCommand

from analysis.services import reap_stale_runs


class Command(BaseCommand):
    help = '워커 중단으로 RUNNING에 고착된 분석 실행을 FAILED로 정리한다.'

    def handle(self, *args, **options):
        reaped = reap_stale_runs()
        self.stdout.write(f'정리한 실행: {reaped}건')
