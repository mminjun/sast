"""기존 findings에 fingerprint 백필 — DB에 저장된 값만 사용, 파일시스템 접근 없음.

0002(AddField)와 분리한 이유: 같은 마이그레이션(단일 트랜잭션)에 두면 인덱스
생성(deferred SQL)이 백필 UPDATE 뒤로 밀려 PostgreSQL이 "cannot CREATE INDEX ...
pending trigger events"로 거부한다.
"""

from django.db import migrations

# 마이그레이션이 앱 코드를 직접 import하는 것은 보통 피하지만, 여기서는 의도한
# 선택이다 — 핑거프린트 규칙을 catalog/fingerprint.py 한 곳에만 두어 ingest와
# 백필이 갈라질 수 없게 한다. 대신 규칙을 변경하면 과거 데이터 재백필이 필요하다
# (docs/decisions.md 2026-09-02). fingerprint.py는 모델을 import하지 않는 순수
# 함수 모듈이라 historical model과 함께 써도 안전하다.
from catalog.fingerprint import backfill_fingerprints


def backfill(apps, schema_editor):
    backfill_fingerprints(apps.get_model('catalog', 'Finding'))


class Migration(migrations.Migration):

    dependencies = [
        ('catalog', '0002_finding_fingerprint'),
    ]

    operations = [
        # 역방향은 할 일 없음 — 0002 롤백이 필드째 제거한다.
        migrations.RunPython(backfill, migrations.RunPython.noop),
    ]
