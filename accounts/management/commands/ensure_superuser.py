"""환경변수로 관리자 계정을 보장한다 (Docker 한 줄 실행 — docs/decisions.md 2026-09-07, SFR-001·SFR-003).

컨테이너 진입 스크립트(docker/entrypoint.py)가 migrate·seed_catalog 뒤에 부른다. 이 시스템은 가입이
없어 관리자 계정이 없으면 로그인 자체가 불가능하므로, "뜬다"가 의미를 가지려면 첫 기동에서 관리자가
만들어져야 한다. Django 표준 `createsuperuser --noinput`을 쓰지 않는 이유:
  - 이미 있으면 오류가 아니라 건너뛰어야 한다 (재기동마다 돈다 — 멱등).
  - 비-대화 모드는 비밀번호 검증기를 돌리지 않는다. 여기서는 AUTH_PASSWORD_VALIDATORS를 돌려 약한 값이면
    기동을 멈춘다 — 보안 도구의 기본값은 안전 쪽이어야 한다.
  - .env.example의 placeholder(change-me…)는 길고 흔한 목록에도 없어 검증기를 통과한다(컨테이너에서 실측).
    그대로 두면 공개된 문자열이 관리자 비밀번호가 되므로 placeholder는 명시적으로 거부한다.

환경변수: DJANGO_SUPERUSER_EMAIL, DJANGO_SUPERUSER_PASSWORD (Django의 createsuperuser와 같은 이름).
둘 다 비어 있으면 안내만 하고 정상 종료한다 — 이미 관리자가 있는 환경에서 .env에 자격증명을 남길 필요가 없다.

사용:
    python manage.py ensure_superuser
"""

import os

from django.contrib.auth import get_user_model
from django.contrib.auth.password_validation import validate_password
from django.core.exceptions import ValidationError
from django.core.management.base import BaseCommand, CommandError

EMAIL_VAR = 'DJANGO_SUPERUSER_EMAIL'
PASSWORD_VAR = 'DJANGO_SUPERUSER_PASSWORD'
# .env.example의 placeholder 표식. 값 안에 이 문자열이 있으면 "채우지 않은 것"으로 본다.
PLACEHOLDER_MARK = 'change-me'


class Command(BaseCommand):
    help = (
        f'{EMAIL_VAR}/{PASSWORD_VAR}로 관리자 계정을 만든다. 이미 있으면 건너뛰고, '
        '비밀번호가 검증기를 통과하지 못하면 실패한다 (컨테이너 진입 스크립트용, 멱등).'
    )

    def handle(self, *args, **options):
        email = os.getenv(EMAIL_VAR, '').strip()
        password = os.getenv(PASSWORD_VAR, '')
        if not email and not password:
            self.stdout.write(
                f'{EMAIL_VAR}/{PASSWORD_VAR}가 없어 관리자 계정을 만들지 않습니다. '
                '필요하면 .env에 두 값을 넣고 다시 기동하거나 `manage.py createsuperuser`를 실행하세요.'
            )
            return
        if not email or not password:
            raise CommandError(f'{EMAIL_VAR}와 {PASSWORD_VAR}는 함께 지정해야 합니다.')

        User = get_user_model()
        email = User.objects.normalize_email(email)
        if User.objects.filter(email__iexact=email).exists():
            self.stdout.write(f'관리자 계정 {email}이(가) 이미 있어 건너뜁니다.')
            return

        if PLACEHOLDER_MARK in password.lower():
            raise CommandError(
                f'{PASSWORD_VAR}가 .env.example의 placeholder 그대로입니다 — 실제 비밀번호로 바꾼 뒤 다시 기동하세요.'
            )
        try:
            validate_password(password, user=User(email=email))
        except ValidationError as exc:
            raise CommandError(
                f'{PASSWORD_VAR}가 비밀번호 규칙을 통과하지 못했습니다: ' + ' '.join(exc.messages)
                + ' — .env의 값을 바꾼 뒤 다시 기동하세요.'
            )

        User.objects.create_superuser(email=email, password=password)
        self.stdout.write(self.style.SUCCESS(f'관리자 계정 {email}을(를) 만들었습니다.'))
