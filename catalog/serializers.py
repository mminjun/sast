"""진단 기준·결과 직렬화 (SFR-013, SFR-016).

두 응답 모두 읽기 전용이다. 카탈로그는 시드 커맨드로만 바뀌고(SFR-012), 진단 결과는
Semgrep 실행 결과를 표준화한 것이라 API로 수정할 대상이 아니다 — 쓰기 필드를 두지
않으면 잘못 열릴 여지 자체가 없다 (SEC-004의 기본 차단과 같은 원칙).
"""

from rest_framework import serializers

from .models import DiagnosticRule, Finding, FindingStatus


class DiagnosticRuleSerializer(serializers.ModelSerializer):
    """KISA 진단 기준 49개 조회 (SFR-013, TST-006).

    id 대신 code를 식별자로 내보낸다 — KISA-IV-01은 가이드와 대조 가능한 의미 있는
    값이고, 순차 PK를 밖으로 노출할 이유가 없다.
    """

    # 화면에 그대로 쓸 한글 표기. 프론트에서 코드값→한글 표를 다시 만들면
    # 서버와 어긋날 수 있으므로 서버가 함께 내려준다.
    category_label = serializers.CharField(source='get_category_display', read_only=True)
    severity_label = serializers.CharField(source='get_severity_display', read_only=True)
    # 저장 컬럼이 아니라 semgrep_rule_ids에서 파생되는 값 (catalog/models.py).
    is_implemented = serializers.BooleanField(read_only=True)

    class Meta:
        model = DiagnosticRule
        fields = (
            'code',
            'name',
            'category',
            'category_label',
            'severity',
            'severity_label',
            # 등급을 왜 그렇게 매겼는지 함께 내려준다 — 가이드에 항목별 등급이 없어
            # 우리가 판단한 값이므로, 근거 없이 등급만 보이면 설명할 수 없다 (QLT-004).
            'severity_reason',
            'description',
            'is_implemented',
            'semgrep_rule_ids',
            'extra',
        )
        read_only_fields = fields


class FindingSerializer(serializers.ModelSerializer):
    """표준화된 진단 결과 조회 (SFR-016, SFR-017).

    run은 내보내지 않는다 — 이 응답은 항상 특정 실행 아래에 중첩되어 조회되므로
    중복이고, 실행 식별자를 결과마다 반복할 이유가 없다.
    """

    severity_label = serializers.CharField(source='get_severity_display', read_only=True)
    # 유형은 카탈로그 항목에서 온다. 매핑에 실패한 결과(rule=None)도 목록에 남으므로
    # 점 표기 source 대신 명시적으로 처리한다.
    category = serializers.SerializerMethodField()
    category_label = serializers.SerializerMethodField()
    # 판정(오탐 관리). 쓰기는 별도 엔드포인트(FindingStatusSerializer)로만 — 이 응답은
    # 여전히 읽기 전용이다.
    status_label = serializers.CharField(source='get_status_display', read_only=True)
    status_changed_by = serializers.SerializerMethodField()

    class Meta:
        model = Finding
        fields = (
            'id',
            'status',
            'status_label',
            'status_note',
            'status_changed_by',
            'status_changed_at',
            # 분석 시점 스냅샷 — 기준이 나중에 개정돼도 이 분석이 무엇을 보고했는지 남는다.
            'rule_code',
            'rule_name',
            'category',
            'category_label',
            'severity',
            'severity_label',
            'semgrep_check_id',
            # 격리 루트 기준 상대경로만 담긴다 — 절대경로·workspace UUID는 저장 단계에서
            # 이미 제거됐다 (catalog/services.py, SEC-006/SEC-007).
            'file_path',
            'start_line',
            'end_line',
            'message',
            'code_snippet',
            'extra',
        )
        read_only_fields = fields

    def get_category(self, finding):
        return finding.rule.category if finding.rule_id else ''

    def get_category_label(self, finding):
        return finding.rule.get_category_display() if finding.rule_id else ''

    def get_status_changed_by(self, finding):
        # 접근 로그와 같은 식별자(email)로 내려준다 — 화면의 "누가 판정했나"와 로그를
        # 같은 값으로 대조할 수 있게.
        return finding.status_changed_by.email if finding.status_changed_by_id else None


class FindingStatusSerializer(serializers.Serializer):
    """판정 변경 입력 (PATCH /api/findings/{id}/status/, 관리자 전용).

    Finding 전체를 쓰기 가능하게 열지 않고 판정 두 필드만 받는다 — 표준화된 결과
    본문(경로·줄·메시지)은 여전히 API로 수정할 대상이 아니다.
    """

    status = serializers.ChoiceField(choices=FindingStatus.choices)
    note = serializers.CharField(
        max_length=200, allow_blank=True, required=False, default='', trim_whitespace=True,
    )
