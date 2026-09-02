"""KISA 진단 기준·표준화된 진단 결과 모델 (DAR-006, DAR-007, DAR-009, SFR-013, SFR-014).

이 앱이 plan.md §4의 6테이블 설계에서 마지막 두 개(rules, findings)를 담당한다.
analysis 앱이 Semgrep 원본 JSON(AnalysisRun.raw_result)까지만 책임지고, 그것을
KISA 49개 기준에 맞춰 표준화하는 것은 여기부터다 (QLT-001 책임 분리).
"""

from django.db import models

from analysis.models import AnalysisRun


class Severity(models.TextChoices):
    """표준 심각도 (QLT-004).

    Semgrep의 ERROR/WARNING/INFO를 그대로 쓰지 않고 우리 등급으로 통일한다.
    등급 결정 로직은 catalog/services.py의 normalize_severity() 한 곳에만 둔다 —
    여러 곳에 흩어지면 같은 취약점이 화면마다 다른 등급으로 보인다.
    """

    HIGH = 'HIGH', '높음'
    MEDIUM = 'MEDIUM', '보통'
    LOW = 'LOW', '낮음'


class KisaCategory(models.TextChoices):
    """KISA 소프트웨어 보안약점 진단가이드(2021.11)의 7개 유형.

    항목 코드 `KISA-<유형약어>-<절 내 순번>`의 유형약어가 이 값이다.
    유형은 언어가 아니라 보안약점의 성격 분류라, 분석 대상 언어가 늘어도
    이 목록과 49개 항목은 바뀌지 않는다 (SFR-010, QLT-003).
    """

    IV = 'IV', '입력데이터 검증 및 표현'
    SF = 'SF', '보안기능'
    TS = 'TS', '시간 및 상태'
    EH = 'EH', '에러처리'
    CE = 'CE', '코드오류'
    EN = 'EN', '캡슐화'
    AA = 'AA', 'API 오용'


class DiagnosticRuleQuerySet(models.QuerySet):
    """'실탐지 구현됨'의 정의를 한 곳에 둔다.

    DiagnosticRule.is_implemented 프로퍼티와 같은 판정을 DB 쪽에서도 쓸 수 있게
    맞춰 둔 것이다. 두 판정이 갈라지면 목록 필터 결과와 상세 화면 표시가
    어긋난다.
    """

    def implemented(self):
        return self.exclude(semgrep_rule_ids=[])

    def not_implemented(self):
        return self.filter(semgrep_rule_ids=[])


class DiagnosticRule(models.Model):
    """KISA 진단 기준 49개 (DAR-007, SFR-013).

    49개 전부를 등록하되 실제 Semgrep 룰이 붙은 항목은 일부다(멘토 승인,
    docs/decisions.md). 어느 항목이 실탐지되는지는 이 행에 플래그를 손으로
    켜 두는 것이 아니라 semgrep_rule_ids가 채워졌는지로 판정한다 —
    시드 커맨드가 catalog/rules/*.yaml을 스캔해 채우므로, 룰 YAML을 하나
    추가하고 시드를 다시 돌리면 코드 수정 없이 상태가 바뀐다 (SFR-012, QLT-002).
    """

    code = models.CharField(
        '항목 코드',
        max_length=32,
        unique=True,
        help_text='KISA-IV-01 형식. 유형약어 + 절 내 순번.',
    )
    name = models.CharField('항목명', max_length=200)
    category = models.CharField(
        '유형',
        max_length=2,
        choices=KisaCategory.choices,
    )
    severity = models.CharField(
        '심각도',
        max_length=6,
        choices=Severity.choices,
        help_text='KISA 유형 성격에 따라 개발자가 확정한 등급 (docs/decisions.md).',
    )
    # 등급을 왜 그렇게 매겼는지를 데이터로 들고 다닌다. 가이드에 항목별 등급이 없어
    # 우리가 판단한 값이므로, 근거 없이 숫자만 남으면 설명할 수 없다 (QLT-004).
    severity_reason = models.TextField('심각도 사유', blank=True)
    description = models.TextField('설명', blank=True)

    # 이 항목을 탐지하는 Semgrep 룰 id 목록. 시드 커맨드가 룰 YAML의
    # metadata.kisa_code를 읽어 채운다 — 매핑의 단일 원본은 YAML 쪽이다.
    semgrep_rule_ids = models.JSONField('연결된 Semgrep 룰', default=list, blank=True)
    # CWE 번호·참고 링크 등 항목마다 있을 수도 없을 수도 있는 부가정보 (DAR-009).
    extra = models.JSONField('부가정보', default=dict, blank=True)

    created_at = models.DateTimeField('생성 일시', auto_now_add=True)
    updated_at = models.DateTimeField('수정 일시', auto_now=True)

    objects = DiagnosticRuleQuerySet.as_manager()

    class Meta:
        db_table = 'catalog_rule'
        ordering = ('code',)
        verbose_name = '진단 기준'
        verbose_name_plural = '진단 기준'

    def __str__(self):
        return f'{self.code} {self.name}'

    @property
    def is_implemented(self):
        """실제 Semgrep 룰이 연결돼 탐지되는 항목인지 (SFR-013)."""
        return bool(self.semgrep_rule_ids)


class Finding(models.Model):
    """표준화된 진단 결과 1건 (DAR-006, SFR-014).

    Semgrep 원본 JSON은 AnalysisRun.raw_result에 그대로 남고, 여기에는 KISA
    기준으로 정규화한 형태만 저장한다. 원본을 지우지 않으므로 표준화 로직이
    바뀌면 재수집(ingest)으로 다시 만들 수 있다.
    """

    run = models.ForeignKey(
        AnalysisRun,
        on_delete=models.CASCADE,
        related_name='findings',
        verbose_name='분석 실행',
    )
    # 매핑에 실패한 결과도 버리지 않는다 — 룰 YAML의 kisa_code 오타 같은 상황에서
    # 탐지 결과가 조용히 사라지는 편보다 등급을 폴백으로 매겨 남기는 편이 안전하다.
    # 카탈로그 항목은 삭제 API가 없고 삭제되면 이 결과의 근거가 사라지므로 PROTECT.
    rule = models.ForeignKey(
        DiagnosticRule,
        on_delete=models.PROTECT,
        related_name='findings',
        null=True,
        blank=True,
        verbose_name='진단 기준',
    )

    # 분석 시점 스냅샷 (DAR-008은 비목표 — plan.md §5의 "심각도·명칭 복사만").
    # 기준이 나중에 개정돼도 이 분석이 무엇을 무슨 등급으로 보고했는지는 남는다.
    rule_code = models.CharField('항목 코드(스냅샷)', max_length=32, blank=True)
    rule_name = models.CharField('항목명(스냅샷)', max_length=200, blank=True)
    severity = models.CharField(
        '심각도',
        max_length=6,
        choices=Severity.choices,
    )

    semgrep_check_id = models.CharField('Semgrep 룰 id', max_length=255)
    # 격리 루트(source_dir) 기준 상대경로만 저장한다. Semgrep이 돌려주는 절대경로를
    # 그대로 두면 서버 파일시스템 구조와 workspace UUID가 응답으로 새어 나가
    # 작업 영역 격리가 무의미해진다 (SEC-006, SEC-007).
    file_path = models.CharField('파일 경로', max_length=500)
    start_line = models.PositiveIntegerField('시작 줄', default=0)
    end_line = models.PositiveIntegerField('끝 줄', default=0)

    message = models.TextField('메시지', blank=True)
    code_snippet = models.TextField('코드 조각', blank=True)
    # 실행 간 diff의 매칭 키. sha256(룰|경로|공백 정규화한 조각) + ":순번" — 라인
    # 번호는 넣지 않고(줄 밀림에 안정), 같은 run 안 동일 해시는 start_line 순으로
    # 순번을 항상 붙인다(1건뿐이어도 ":1"). 계산은 catalog/fingerprint.py 한 곳에만
    # 두고 ingest와 마이그레이션 백필이 공유한다 (docs/decisions.md 2026-09-02).
    fingerprint = models.CharField('핑거프린트', max_length=80, default='', db_index=True)
    # 룰 metadata에서 가져온 cwe·references 등 (DAR-009).
    extra = models.JSONField('부가정보', default=dict, blank=True)

    created_at = models.DateTimeField('생성 일시', auto_now_add=True)

    class Meta:
        db_table = 'catalog_finding'
        # 같은 파일 안에서 줄 순서대로 — 대시보드에서 코드를 따라 읽을 수 있게.
        ordering = ('file_path', 'start_line', 'id')
        verbose_name = '진단 결과'
        verbose_name_plural = '진단 결과'
        indexes = [
            # 심각도 필터(SFR-017)와 항목별 집계가 항상 run 단위로 걸린다.
            models.Index(fields=('run', 'severity'), name='catalog_finding_run_sev'),
            models.Index(fields=('run', 'rule'), name='catalog_finding_run_rule'),
        ]

    def __str__(self):
        return f'[{self.severity}] {self.rule_code or self.semgrep_check_id} {self.file_path}:{self.start_line}'
