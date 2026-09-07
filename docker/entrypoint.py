"""컨테이너 진입 스크립트 (Docker 한 줄 실행 — docs/decisions.md 2026-09-07).

web:    DB 대기 → migrate → seed_catalog(멱등) → ensure_superuser(있으면 건너뜀) → gunicorn
그 외:  DB 대기 → 넘긴 명령 그대로 실행 (worker: manage.py analysis_worker --reap-all)

준비 단계(migrate·seed·관리자)는 web만 한다 — web과 worker가 동시에 migrate를 돌리면 경쟁하므로
worker는 compose에서 web이 healthy(= 준비 끝, 응답 중)가 된 뒤에 뜬다(docker-compose.yml depends_on).

셸 스크립트가 아니라 Python인 이유: 이 저장소는 Windows에서 core.autocrlf=true로 체크아웃되어 .sh가
CRLF로 이미지에 복사되고 `/bin/sh^M`으로 죽는다. Python은 줄 끝을 가리지 않고, Django 커맨드를
call_command로 직접 부를 수 있어 서브프로세스도 필요 없다.
"""

import os
import sys
import time

sys.path.insert(0, '/app')
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'config.settings')

import django  # noqa: E402

django.setup()

from django.core.management import call_command  # noqa: E402
from django.db import connection  # noqa: E402
from django.db.utils import OperationalError  # noqa: E402

DB_WAIT_ATTEMPTS = 30
DB_WAIT_SECONDS = 2


def log(message):
    print(f'[entrypoint] {message}', flush=True)


def wait_for_db():
    """compose의 depends_on(service_healthy)이 주된 대기 수단이고, 이것은 재기동·단독 실행용 보강이다."""
    for attempt in range(1, DB_WAIT_ATTEMPTS + 1):
        try:
            connection.ensure_connection()
            return
        except OperationalError as exc:
            log(f'DB 대기 중 ({attempt}/{DB_WAIT_ATTEMPTS}): {exc}'.rstrip())
            time.sleep(DB_WAIT_SECONDS)
    log('DB에 연결하지 못해 종료합니다. POSTGRES_* 값과 db 컨테이너 상태를 확인하세요.')
    sys.exit(1)


def prepare_web():
    log('migrate')
    call_command('migrate', interactive=False, verbosity=1)
    log('seed_catalog (KISA 진단 기준 49개, 멱등)')
    call_command('seed_catalog', verbosity=1)
    log('ensure_superuser')
    call_command('ensure_superuser')


def main(argv):
    wait_for_db()
    if argv[:1] == ['web']:
        prepare_web()
        # gunicorn: 워커 2개, 타임아웃 300초(200MB zip 업로드 여유). 컨테이너 안에서는 0.0.0.0에 묶고
        # 호스트 노출은 compose가 127.0.0.1로 제한한다.
        log('gunicorn 0.0.0.0:8000')
        os.execvp('gunicorn', [
            'gunicorn', 'config.wsgi:application',
            '--bind', '0.0.0.0:8000', '--workers', '2', '--timeout', '300',
            '--access-logfile', '-',
        ])
    os.execvp(argv[0], argv)


if __name__ == '__main__':
    if len(sys.argv) < 2:
        log('사용: entrypoint.py web | <명령...>')
        sys.exit(2)
    main(sys.argv[1:])
