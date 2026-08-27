"""KISA 진단 기준 49개 등록 + 룰 매핑 갱신 (SFR-012, SFR-013, DAR-007).

데이터 마이그레이션이 아니라 관리 커맨드인 이유: 진단 기준은 가이드 개정으로 바뀌는
참조 데이터라 재실행으로 갱신할 수 있어야 한다. 마이그레이션에 넣으면 기준이 바뀔 때마다
히스토리가 데이터로 오염된다 (docs/decisions.md).

두 곳에서 읽는다.
  - catalog/data/kisa_rules.json — 49개 항목의 이름·유형·심각도·사유 (기준 원본)
  - catalog/rules/*.yaml         — 각 룰의 metadata.kisa_code (룰↔항목 매핑 원본)

매핑을 JSON에도 적어 두면 두 곳이 어긋나므로, 어느 항목이 '실탐지 구현됨'인지는
룰 YAML을 스캔한 결과로만 정한다. 룰 YAML을 하나 추가하고 이 커맨드를 다시 돌리면
코드 수정 없이 카탈로그 상태가 바뀐다 (SFR-012, QLT-002).

사용:
    python manage.py seed_catalog
    python manage.py seed_catalog --dry-run   # DB를 건드리지 않고 결과만 확인
"""

import json

import yaml
from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from django.db import transaction

from catalog.models import DiagnosticRule, KisaCategory, Severity

VALID_CATEGORIES = set(KisaCategory.values)
VALID_SEVERITIES = set(Severity.values)


class Command(BaseCommand):
    help = 'KISA 진단 기준 49개를 등록하고 룰 YAML을 스캔해 매핑을 갱신한다 (SFR-012, SFR-013).'

    def add_arguments(self, parser):
        parser.add_argument(
            '--dry-run',
            action='store_true',
            help='DB에 쓰지 않고 검증 결과와 변경 예정 건수만 출력한다.',
        )

    def handle(self, *args, **options):
        # verbosity=0(테스트 등)에서는 아무것도 찍지 않는다. 검증 실패는 CommandError로
        # 올라가므로 출력을 줄여도 조용히 넘어가지 않는다.
        self.verbosity = options['verbosity']

        seed = self._load_seed()
        mapping = self._scan_rule_files()
        self._check_drift(seed, mapping)

        if options['dry_run']:
            self._report_dry_run(seed, mapping)
            return

        created, updated = self._upsert(seed, mapping)
        self._report(seed, mapping, created, updated)

    # ------------------------------------------------------------------
    # 읽기·검증
    # ------------------------------------------------------------------

    def _load_seed(self):
        """시드 JSON을 읽고 자체 정합성을 확인한다.

        여기서 걸러내지 않으면 잘못된 유형·심각도가 DB까지 내려가, 나중에
        필터가 조용히 아무것도 반환하지 않는 형태로 드러난다.
        """
        path = settings.CATALOG_SEED_FILE
        if not path.exists():
            raise CommandError(f'시드 파일이 없습니다: {path}')

        # 인코딩을 명시한다 — Windows 기본 로케일 코덱(cp949)으로 읽으면 한글에서 깨진다.
        try:
            data = json.loads(path.read_text(encoding='utf-8'))
        except json.JSONDecodeError as exc:
            raise CommandError(f'시드 파일이 올바른 JSON이 아닙니다: {exc}') from exc

        rules = data.get('rules')
        if not isinstance(rules, list):
            raise CommandError('시드 파일에 rules 배열이 없습니다.')

        declared_total = data.get('total')
        if declared_total is not None and declared_total != len(rules):
            raise CommandError(
                f'선언된 total({declared_total})과 실제 항목 수({len(rules)})가 다릅니다 — '
                '항목이 누락됐거나 중복 추가됐을 수 있습니다.'
            )

        codes = [r.get('code', '') for r in rules]
        duplicated = sorted({c for c in codes if codes.count(c) > 1})
        if duplicated:
            raise CommandError(f'중복된 항목 코드: {", ".join(duplicated)}')

        for rule in rules:
            code = rule.get('code')
            if not code:
                raise CommandError(f'code가 없는 항목이 있습니다: {rule}')
            if rule.get('category') not in VALID_CATEGORIES:
                raise CommandError(
                    f'{code}: 알 수 없는 유형 {rule.get("category")!r} '
                    f'(허용: {", ".join(sorted(VALID_CATEGORIES))})'
                )
            if rule.get('severity') not in VALID_SEVERITIES:
                raise CommandError(
                    f'{code}: 알 수 없는 심각도 {rule.get("severity")!r} '
                    f'(허용: {", ".join(sorted(VALID_SEVERITIES))})'
                )

        return rules

    def _scan_rule_files(self):
        """catalog/rules/*.yaml을 읽어 {kisa_code: [semgrep 룰 id, ...]}를 만든다."""
        rules_dir = settings.CATALOG_RULES_DIR
        if not rules_dir.exists():
            raise CommandError(f'룰 디렉토리가 없습니다: {rules_dir}')

        mapping = {}
        for path in sorted(rules_dir.rglob('*.y*ml')):
            try:
                document = yaml.safe_load(path.read_text(encoding='utf-8'))
            except yaml.YAMLError as exc:
                raise CommandError(f'{path.name}: YAML 파싱 실패 — {exc}') from exc

            for rule in (document or {}).get('rules', []):
                rule_id = rule.get('id')
                kisa_code = (rule.get('metadata') or {}).get('kisa_code')
                if not rule_id:
                    raise CommandError(f'{path.name}: id가 없는 룰이 있습니다.')
                if not kisa_code:
                    raise CommandError(
                        f'{path.name}: 룰 {rule_id}에 metadata.kisa_code가 없습니다 — '
                        '카탈로그 항목에 연결되지 않는 룰은 결과를 표준화할 수 없습니다.'
                    )
                mapping.setdefault(kisa_code, []).append(rule_id)

        return {code: sorted(ids) for code, ids in mapping.items()}

    def _check_drift(self, seed, mapping):
        """룰이 가리키는 항목이 카탈로그에 실제로 있는지 확인한다.

        kisa_code 오타를 그대로 두면 탐지는 되는데 매핑이 안 되어 결과가 폴백 등급으로
        조용히 저장된다. 시드 시점에 실패시키는 편이 낫다.
        """
        known = {rule['code'] for rule in seed}
        unknown = sorted(set(mapping) - known)
        if unknown:
            raise CommandError(
                '룰 YAML이 카탈로그에 없는 항목을 가리킵니다: '
                f'{", ".join(unknown)} — kisa_code 오타이거나 시드 데이터에 항목이 빠졌습니다.'
            )

    # ------------------------------------------------------------------
    # 쓰기
    # ------------------------------------------------------------------

    @transaction.atomic
    def _upsert(self, seed, mapping):
        """code를 기준으로 등록·갱신한다 (멱등).

        삭제는 하지 않는다 — 이미 저장된 Finding이 PROTECT로 항목을 참조하고 있어
        지울 수 없고, 지워서도 안 된다(과거 분석 결과의 근거가 사라진다).
        """
        created = updated = 0
        for rule in seed:
            _, was_created = DiagnosticRule.objects.update_or_create(
                code=rule['code'],
                defaults={
                    'name': rule['name'],
                    'category': rule['category'],
                    'severity': rule['severity'],
                    'severity_reason': rule.get('severity_reason', ''),
                    'description': rule.get('description', ''),
                    'semgrep_rule_ids': mapping.get(rule['code'], []),
                    'extra': rule.get('extra', {}),
                },
            )
            if was_created:
                created += 1
            else:
                updated += 1
        return created, updated

    # ------------------------------------------------------------------
    # 출력
    # ------------------------------------------------------------------

    def _report_dry_run(self, seed, mapping):
        if not self.verbosity:
            return
        self.stdout.write(self.style.WARNING('[--dry-run] DB를 변경하지 않았습니다.'))
        self.stdout.write(f'  검증 통과: 시드 {len(seed)}개 항목')
        self.stdout.write(f'  룰 매핑: {len(mapping)}개 항목에 연결됨')

    def _report(self, seed, mapping, created, updated):
        if not self.verbosity:
            return
        implemented = DiagnosticRule.objects.implemented().count()
        total = DiagnosticRule.objects.count()

        self.stdout.write(self.style.SUCCESS(
            f'카탈로그 {len(seed)}개 처리 완료 (신규 {created} / 갱신 {updated})'
        ))
        self.stdout.write(f'  DB 총 항목: {total}개')
        self.stdout.write(f'  실탐지 구현: {implemented}개 / 미구현: {total - implemented}개')

        # 등록된 룰이 어느 항목에 붙었는지 보여준다 — 시연 때 "무엇이 실제로 도는지"를
        # 카탈로그에서 바로 확인할 수 있어야 한다 (TST-006).
        for code in sorted(mapping):
            ids = ', '.join(mapping[code])
            self.stdout.write(f'    {code} ← {ids}')

        stale = DiagnosticRule.objects.exclude(
            code__in=[rule['code'] for rule in seed]
        ).values_list('code', flat=True)
        if stale:
            self.stdout.write(self.style.WARNING(
                f'  시드에 없는 기존 항목(삭제하지 않음): {", ".join(sorted(stale))}'
            ))
