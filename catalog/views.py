"""진단 기준 조회·분석 결과 조회 뷰 (SFR-013, SFR-016, SFR-017, SEC-005, SEC-006).

접근 통제 원칙은 projects·analysis 앱과 같다: 권한을 뷰의 분기문이 아니라 쿼리셋에
건다. 진단 결과는 항상 스코프된 실행(run)을 통해서만 도달하므로, URL의 run id를
조작해도 할당되지 않은 프로젝트의 결과에는 닿을 수 없다 (IDOR 방어, SEC-005).

카탈로그(진단 기준 49개)는 프로젝트에 딸린 데이터가 아니라 공통 기준 문서라 스코프가
없다 — 인증만 요구한다.
"""

from django.db.models import Case, Count, IntegerField, Q, Value, When
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.exceptions import ValidationError
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAdminRole
from analysis.models import AnalysisRun, AnalysisStatus
from analysis.services import run_sequence
from config.access_log import log_access

from projects.models import Project

from .models import DiagnosticRule, Finding, KisaCategory, Severity
from .serializers import DiagnosticRuleSerializer, FindingSerializer
from .services import diff_findings, ingest_findings, run_change_counts

CATEGORY_VALUES = set(KisaCategory.values)
SEVERITY_VALUES = set(Severity.values)

# 심각도 정렬용 순위. CharField라 사전순으로 정렬하면 HIGH < LOW < MEDIUM이 되어
# 위험한 항목이 가운데 묻힌다 — 보안 대시보드는 높은 것이 위에 와야 한다.
SEVERITY_RANK = Case(
    When(severity=Severity.HIGH, then=Value(0)),
    When(severity=Severity.MEDIUM, then=Value(1)),
    default=Value(2),
    output_field=IntegerField(),
)


def _scoped_projects(user):
    """analysis/views.py의 같은 이름 함수와 동일한 규칙 (SEC-005).

    각 앱이 자기 책임 안에서 권한을 확인한다 — 뷰 계층을 공유하지 않는다 (QLT-001).
    """
    if user.is_admin:
        return Project.objects.all()
    return Project.objects.filter(memberships__user=user)


def _scoped_analysis_runs(user):
    """관리자=전체, 일반=할당된 프로젝트의 실행만 (SEC-005).

    analysis/views.py의 같은 이름 함수와 동일한 규칙이다. 앱마다 자기 책임 안에서
    권한을 확인하도록 뷰 계층을 공유하지 않는다 (QLT-001, docs/decisions.md).
    클라이언트가 보낸 run id를 신뢰하지 않고 DB의 할당 관계로 재검증한다.
    """
    queryset = AnalysisRun.objects.select_related('project')
    if user.is_admin:
        return queryset
    return queryset.filter(project__memberships__user=user)


def _require_choice(value, allowed, field):
    """알 수 없는 필터 값은 400으로 돌려준다.

    조용히 무시하면 오타 난 필터가 '전체 조회'로 동작하고, 조용히 빈 결과를 주면
    '취약점이 없다'로 오해된다 — 보안 도구에서 둘 다 위험한 실패 방식이다.
    """
    if value and value not in allowed:
        raise ValidationError({
            field: [f'허용되지 않은 값입니다: {value} (허용: {", ".join(sorted(allowed))})']
        })
    return value


def _require_bool(value, field):
    if value is None or value == '':
        return None
    lowered = value.strip().lower()
    if lowered in ('true', '1'):
        return True
    if lowered in ('false', '0'):
        return False
    raise ValidationError({field: [f'true 또는 false여야 합니다: {value}']})


class DiagnosticRuleListView(generics.ListAPIView):
    """KISA 진단 기준 49개 목록 (SFR-013, TST-006).

    구현 여부와 무관하게 49개를 모두 등록·조회한다 — 실제 탐지되는 항목은 일부지만
    (멘토 승인), 기준 자체는 전부 보여야 어떤 항목이 아직 대상 언어 밖인지 드러난다.
    """

    serializer_class = DiagnosticRuleSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        params = self.request.query_params
        queryset = DiagnosticRule.objects.all()

        category = _require_choice(params.get('category'), CATEGORY_VALUES, 'category')
        if category:
            queryset = queryset.filter(category=category)

        severity = _require_choice(params.get('severity'), SEVERITY_VALUES, 'severity')
        if severity:
            queryset = queryset.filter(severity=severity)

        implemented = _require_bool(params.get('implemented'), 'implemented')
        if implemented is True:
            queryset = queryset.implemented()
        elif implemented is False:
            queryset = queryset.not_implemented()

        keyword = (params.get('q') or '').strip()
        if keyword:
            queryset = queryset.filter(
                Q(code__icontains=keyword)
                | Q(name__icontains=keyword)
                | Q(description__icontains=keyword)
            )

        return queryset


class DiagnosticRuleDetailView(generics.RetrieveAPIView):
    """진단 기준 1건 상세 (SFR-013).

    조회 키는 순차 PK가 아니라 code(KISA-IV-01)다 — 가이드와 대조할 수 있는 값이고
    숫자 id를 밖으로 노출하지 않는다.
    """

    serializer_class = DiagnosticRuleSerializer
    permission_classes = [IsAuthenticated]
    queryset = DiagnosticRule.objects.all()
    lookup_field = 'code'
    # 형식에 맞지 않는 값은 URL 매칭 단계에서 404로 떨어뜨린다 (projects 앱과 같은 원칙).
    lookup_value_regex = r'[A-Za-z0-9\-]+'


class CatalogSummaryView(APIView):
    """카탈로그 현황 집계 (TST-006 시연용).

    "49개 중 몇 개가 실제로 탐지되는가"를 한 번에 보여준다 — 부분 구현이 의도된
    범위라는 것을 숫자로 설명하기 위한 응답이다.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request):
        queryset = DiagnosticRule.objects.all()
        total = queryset.count()
        implemented = queryset.implemented().count()

        by_category = []
        category_counts = {
            row['category']: row for row in
            queryset.values('category').annotate(
                total=Count('id'),
                implemented=Count('id', filter=~Q(semgrep_rule_ids=[])),
            )
        }
        # 항목이 하나도 없는 유형도 0으로 내려준다 — 화면이 유형 목록을 따로 갖지
        # 않아도 되고, 빠진 유형과 0건인 유형을 구분할 수 있다.
        for value, label in KisaCategory.choices:
            row = category_counts.get(value, {})
            by_category.append({
                'category': value,
                'label': label,
                'total': row.get('total', 0),
                'implemented': row.get('implemented', 0),
            })

        severity_counts = dict(
            queryset.values_list('severity').annotate(n=Count('id'))
        )
        by_severity = [
            {'severity': value, 'label': label, 'total': severity_counts.get(value, 0)}
            for value, label in Severity.choices
        ]

        return Response({
            'total': total,
            'implemented': implemented,
            'not_implemented': total - implemented,
            'by_category': by_category,
            'by_severity': by_severity,
        })


class FindingPagination(PageNumberPagination):
    """진단 결과 목록에만 적용하는 페이지네이션.

    전역(REST_FRAMEWORK 설정)으로 걸지 않는 이유: 이미 만들어진 accounts·projects·
    analysis 응답 형태가 함께 바뀌어 회귀가 된다. 상한이 필요한 곳은 결과 목록
    하나뿐이다 — 한 실행에서 파일 1000개(SEC-008 상한)에 걸쳐 수천 건이 나올 수
    있고, 건마다 코드 조각이 붙어 응답이 수 MB가 된다.
    """

    page_size = 50
    page_size_query_param = 'page_size'
    max_page_size = 200


class RunFindingsMixin:
    """진단 결과 계열 뷰의 공통 조회 경로.

    실행은 반드시 스코프된 쿼리셋으로 얻는다 — 중첩 자원에서 부모의 권한 검증을
    건너뛰는 것이 IDOR의 전형적인 경로다 (projects 앱 members 액션과 같은 이유).
    스코프 밖 run과 존재하지 않는 run이 똑같이 404가 되므로, 응답 차이로 실행의
    존재를 알아낼 수 없다 (SEC-006).
    """

    def get_run(self):
        # 한 요청에서 여러 번 불려도(쿼리셋 구성 → 접근 로그) 조회는 한 번만 한다.
        if not hasattr(self, '_run'):
            self._run = get_object_or_404(
                _scoped_analysis_runs(self.request.user),
                pk=self.kwargs['run_id'],
            )
        return self._run


class RunFindingListView(RunFindingsMixin, generics.ListAPIView):
    """분석 결과 목록 + 심각도·유형 필터 (SFR-016, SFR-017)."""

    serializer_class = FindingSerializer
    permission_classes = [IsAuthenticated]
    pagination_class = FindingPagination

    def list(self, request, *args, **kwargs):
        response = super().list(request, *args, **kwargs)
        # 스코프·필터 검증을 통과해 응답이 만들어진 뒤에만 남긴다 (404·400 제외).
        run = self.get_run()
        log_access(request.user, 'findings_list', run_id=run.pk, project_id=run.project_id)
        return response

    def get_queryset(self):
        run = self.get_run()
        params = self.request.query_params
        # rule을 함께 읽는다 — 응답의 category가 rule을 참조하므로 N+1을 피한다.
        queryset = Finding.objects.filter(run=run).select_related('rule')

        severity = _require_choice(params.get('severity'), SEVERITY_VALUES, 'severity')
        if severity:
            queryset = queryset.filter(severity=severity)

        category = _require_choice(params.get('category'), CATEGORY_VALUES, 'category')
        if category:
            queryset = queryset.filter(rule__category=category)

        code = (params.get('rule') or '').strip()
        if code:
            # 스냅샷 컬럼으로 찾는다 — 매핑에 실패한 결과도 자기가 주장한 코드로
            # 검색되어야 한다.
            queryset = queryset.filter(rule_code=code)

        keyword = (params.get('q') or '').strip()
        if keyword:
            queryset = queryset.filter(
                Q(message__icontains=keyword)
                | Q(file_path__icontains=keyword)
                | Q(rule_name__icontains=keyword)
            )

        return queryset.annotate(severity_rank=SEVERITY_RANK).order_by(
            'severity_rank', 'file_path', 'start_line', 'id'
        )


class RunFindingSummaryView(RunFindingsMixin, APIView):
    """실행 1건의 결과 집계 — 대시보드 상단용 (SFR-016)."""

    permission_classes = [IsAuthenticated]

    def get(self, request, run_id):
        run = self.get_run()
        log_access(request.user, 'findings_summary', run_id=run.pk, project_id=run.project_id)
        findings = Finding.objects.filter(run=run)

        severity_counts = dict(findings.values_list('severity').annotate(n=Count('id')))
        # 0건인 등급도 키를 채워 내려준다 — 화면이 키 부재와 0건을 구분하지 않아도 되게.
        by_severity = [
            {'severity': value, 'label': label, 'total': severity_counts.get(value, 0)}
            for value, label in Severity.choices
        ]

        by_rule = [
            {
                'rule_code': row['rule_code'],
                'rule_name': row['rule_name'],
                'severity': row['severity'],
                'total': row['total'],
            }
            for row in findings.values('rule_code', 'rule_name', 'severity')
            .annotate(total=Count('id'))
            .annotate(severity_rank=SEVERITY_RANK)
            .order_by('severity_rank', '-total', 'rule_code')
        ]

        return Response({
            'run': run.pk,
            'status': run.status,
            'total': findings.count(),
            'by_severity': by_severity,
            'by_rule': by_rule,
        })


class RunDiffView(RunFindingsMixin, APIView):
    """실행 간 비교 — 직전(또는 지정) 실행 대비 신규/해결/유지 (RFP 외 자체 개선).

    읽기 전용이라 접근 권한은 다른 결과 조회와 동일하다(일반 사용자도 할당
    프로젝트면 조회 가능). 계산 규칙은 catalog/services.py의 diff_findings 참고.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, run_id):
        target = self.get_run()
        if target.status != AnalysisStatus.SUCCEEDED:
            raise ValidationError(
                {'detail': ['완료(SUCCEEDED)된 실행만 비교할 수 있습니다.']}
            )
        base, auto_selected = self._resolve_base(request, target)

        result = diff_findings(base, target)
        log_access(request.user, 'run_diff', run_id=target.pk, project_id=target.project_id)

        payload = {
            'target': self._run_meta(target),
            'base': self._run_meta(base) if base else None,
            'base_auto_selected': auto_selected,
            **result,
        }
        if base is None:
            payload['note'] = '비교할 이전 완료된 분석이 없어 전체를 신규로 표시합니다.'
        return Response(payload)

    def _resolve_base(self, request, target):
        """비교 기준 실행. ?base= 명시가 없으면 같은 프로젝트의 직전 완료 실행."""
        raw = (request.query_params.get('base') or '').strip()
        if not raw:
            previous = (
                AnalysisRun.objects
                .filter(project_id=target.project_id, status=AnalysisStatus.SUCCEEDED)
                .exclude(pk=target.pk)
                # "직전"은 생성 시각 기준, 동시각이면 pk로 — 자동 선택이 요청마다
                # 다른 실행을 고르면 diff 결과가 재현되지 않는다.
                .filter(
                    Q(created_at__lt=target.created_at)
                    | Q(created_at=target.created_at, pk__lt=target.pk)
                )
                .order_by('-created_at', '-pk')
                .first()
            )
            return previous, True

        if not raw.isdigit():
            raise ValidationError({'base': ['실행 id(정수)여야 합니다.']})
        base_id = int(raw)
        if base_id == target.pk:
            raise ValidationError({'base': ['대상 실행 자신과는 비교할 수 없습니다.']})
        # target 프로젝트로 한정해 조회한다 — 다른 프로젝트의 실행과 존재하지 않는
        # 실행이 같은 응답이 되어, base id를 바꿔 넣어도 실행의 존재 여부를 알아낼
        # 수 없다 (SEC-006). target이 이미 스코프를 통과했으므로 같은 프로젝트의
        # 실행은 전부 열람 권한 안이다.
        base = AnalysisRun.objects.filter(
            project_id=target.project_id, pk=base_id,
        ).first()
        if base is None:
            raise ValidationError({'base': ['같은 프로젝트의 실행이어야 합니다.']})
        if base.status != AnalysisStatus.SUCCEEDED:
            raise ValidationError(
                {'base': ['완료(SUCCEEDED)된 실행만 비교할 수 있습니다.']}
            )
        return base, False

    @staticmethod
    def _run_meta(run):
        return {
            'id': run.pk,
            # 화면 표시는 프로젝트 내 회차("N번째 분석") — 식별자는 여전히 id.
            'sequence': run_sequence(run),
            'status': run.status,
            'original_filename': run.original_filename,
            'created_at': run.created_at,
        }


class ProjectRunChangesView(APIView):
    """실행 이력의 직전 완료 대비 변화량 — 실행 목록 표시용 (RFP 외 자체 개선).

    실행마다 diff API를 호출하면 목록 렌더링에 N개의 요청이 필요해진다.
    diff는 catalog 책임이므로 analysis의 목록 API를 확장하는 대신(역방향 의존
    금지, QLT-001) 여기서 프로젝트 단위로 한 번에 내려준다.
    """

    permission_classes = [IsAuthenticated]

    def get(self, request, project_id):
        # 미할당·미존재 프로젝트는 동일한 404 (SEC-006).
        project = get_object_or_404(_scoped_projects(request.user), pk=project_id)
        changes = run_change_counts(project.pk)
        log_access(request.user, 'run_changes', project_id=project.pk)
        return Response({'changes': changes})


class RunFindingReingestView(RunFindingsMixin, APIView):
    """저장된 원본 결과를 다시 표준화한다 (SFR-014, 관리자 전용).

    필요한 경우는 둘이다. (1) 룰을 추가하거나 카탈로그 등급을 조정한 뒤 과거 분석에
    반영할 때, (2) 표준화가 실패해 결과가 비어 있을 때(catalog/receivers.py는 표준화
    실패를 삼키고 로그만 남기므로, 복구 경로가 여기다).

    Semgrep을 다시 돌리지 않는다 — raw_result가 그대로 남아 있어 재분석 없이 변환만
    다시 하면 된다.
    """

    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request, run_id):
        run = self.get_run()
        if run.raw_result is None:
            return Response(
                {'detail': '표준화할 원본 결과가 없습니다. 분석을 먼저 실행하세요.'},
                status=status.HTTP_409_CONFLICT,
            )

        result = ingest_findings(run)
        return Response({
            'run': run.pk,
            'created': result.created,
            'skipped': result.skipped,
            'unmapped': result.unmapped,
        })
