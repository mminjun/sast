"""분석 실행 워커 (SFR-008~009, SEC-009).

django-tasks-db의 `db_worker`를 그대로 상속한다 — 옵션(--interval, --worker-id, --batch,
--max-tasks, --reload …)은 전부 물려받고, 시작 시 고착된 RUNNING 실행을 먼저 정리하는
것만 더한다. 정리를 수동 커맨드(reap_stale_runs)에만 두면 아무도 돌리지 않으므로
반드시 실행되는 진입점인 워커 시작에 붙인다. 멱등이라 --reload(DEBUG 기본) 재시작마다
다시 돌아도 무해하다.

이름을 `db_worker`로 덮어쓰지 않는 이유: Django는 INSTALLED_APPS 앞쪽 앱의 동명 커맨드가
이기므로(get_commands가 reversed 순서로 update) 덮어쓰기는 앱 순서에 묶인다.

동시 실행 수 = 워커 프로세스 수. 한 프로세스는 한 번에 한 작업만 처리하고, 두 개 이상
띄우려면 --worker-id를 서로 다르게 준다 (README "분석 워커").

사용:
    python manage.py analysis_worker              # venv 활성화 상태 — semgrep이 PATH에 있어야 한다
    python manage.py analysis_worker --batch      # 밀린 작업만 처리하고 종료
"""

from django_tasks_db.management.commands.db_worker import Command as DbWorkerCommand

from analysis.services import reap_stale_runs


class Command(DbWorkerCommand):
    help = (
        '분석 실행 큐 워커. 시작 시 고착된 RUNNING 실행을 FAILED로 정리한 뒤 '
        '큐(django_tasks_db)의 작업을 순서대로 처리한다.'
    )

    def handle(self, *args, **options):
        reaped = reap_stale_runs()
        if reaped:
            self.stdout.write(
                self.style.WARNING(
                    f'고착된 RUNNING 실행 {reaped}건을 FAILED로 정리했습니다 (워커 중단 추정).'
                )
            )
        super().handle(*args, **options)
