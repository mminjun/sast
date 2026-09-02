"""분석 실행 뷰 — 업로드·조회·실행 (SFR-007~009, SEC-005~007).

projects 앱과 같은 원칙: 권한을 뷰의 분기문이 아니라 쿼리셋에 건다.
project_id·run id는 항상 스코프된 쿼리셋을 거쳐 조회하므로, URL의 id를
조작해도 스코프 밖 행에는 도달할 수 없다 (IDOR 방어, SEC-005).
"""

from django.conf import settings
from django.db.models import Count, Q
from django.shortcuts import get_object_or_404
from rest_framework import generics, status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from accounts.permissions import IsAdminRole
from config.access_log import log_access
from projects.models import Project

from .models import AnalysisRun
from .serializers import AnalysisRunSerializer, AnalysisRunUploadSerializer
from .services import run_semgrep, start_run


def _scoped_projects(user):
    """projects/views.py의 ProjectViewSet.get_queryset()과 동일한 규칙.

    관리자=전체, 일반=할당된 프로젝트만 (SEC-005). 두 앱이 각자 책임을 지므로
    뷰 클래스를 공유하지 않고 이 짧은 필터만 반복한다 (QLT-001).
    """
    if user.is_admin:
        return Project.objects.all()
    return Project.objects.filter(memberships__user=user)


def _with_severity_counts(queryset):
    """실행별 심각도 건수를 목록 쿼리 한 번에 계산한다 (SFR-016, N+1 방지).

    Finding은 catalog 앱 소유지만 여기서는 역참조 이름(findings)과 severity 값
    문자열만 쓰고 모듈은 import하지 않는다 — 확장자 목록을 룰 YAML에서 파생하지
    않은 것과 같은 이유로 analysis→catalog 역방향 의존을 만들지 않는다 (QLT-001).
    """
    return queryset.annotate(
        num_high=Count('findings', filter=Q(findings__severity='HIGH')),
        num_medium=Count('findings', filter=Q(findings__severity='MEDIUM')),
        num_low=Count('findings', filter=Q(findings__severity='LOW')),
    )


def _scoped_analysis_runs(user):
    """분석 실행도 같은 규칙으로 스코프한다 — project 관계를 거쳐 재검증."""
    queryset = AnalysisRun.objects.select_related('project', 'created_by')
    if user.is_admin:
        return queryset
    return queryset.filter(project__memberships__user=user)


class ProjectAnalysisRunsView(APIView):
    """프로젝트에 속한 분석 실행 목록 조회·zip 업로드 (SFR-007, SFR-016 전 단계).

    project_id는 스코프된 프로젝트 쿼리셋으로만 조회한다 — 미할당·존재하지 않는
    프로젝트는 동일하게 404 (SEC-006, projects 앱과 같은 응답 정책).
    """

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsAuthenticated(), IsAdminRole()]
        return [IsAuthenticated()]

    def get_project(self):
        return get_object_or_404(_scoped_projects(self.request.user), pk=self.kwargs['project_id'])

    def get(self, request, project_id):
        project = self.get_project()
        # annotate(집계)가 붙으면 Django가 Meta 기본 정렬을 제거한다 — 같은 분에
        # 생성된 실행들이 요청마다 뒤섞이던 원인. 명시적으로 다시 고정한다.
        runs = list(
            _with_severity_counts(project.analysis_runs.select_related('created_by'))
            .order_by('-created_at', '-pk')
        )
        # 회차는 목록 전체를 이미 들고 있으므로 자리에서 계산한다(쿼리 0회).
        # 목록은 (-created_at, -id) 정렬이라 아래(가장 오래된 실행)가 1회차다.
        total = len(runs)
        for index, run in enumerate(runs):
            run.sequence_no = total - index
        return Response(AnalysisRunSerializer(runs, many=True).data)

    def post(self, request, project_id):
        project = self.get_project()
        serializer = AnalysisRunUploadSerializer(
            data=request.data,
            context={
                'project': project,
                'request': request,
                'max_upload_size': settings.ANALYSIS_MAX_UPLOAD_SIZE,
            },
        )
        serializer.is_valid(raise_exception=True)
        run = serializer.save()
        return Response(AnalysisRunSerializer(run).data, status=status.HTTP_201_CREATED)


class AnalysisRunDetailView(generics.RetrieveAPIView):
    """분석 실행 상세 조회 — 상태·결과 확인 (SFR-015, SFR-016 전 단계)."""

    serializer_class = AnalysisRunSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        return _with_severity_counts(_scoped_analysis_runs(self.request.user))

    def retrieve(self, request, *args, **kwargs):
        run = self.get_object()
        # 스코프 검증을 통과한 열람만 남긴다 — 404는 열람이 아니다.
        log_access(request.user, 'run_detail', run_id=run.pk, project_id=run.project_id)
        return Response(self.get_serializer(run).data)


class AnalysisRunExecuteView(APIView):
    """분석 실행 트리거 (SFR-008~009, 관리자 전용).

    업로드(소스 등록)와 실행을 분리한 API 2단계 중 두 번째 — 대기/실행중/완료/실패
    4개 상태가 실제로 관찰 가능하고, 업로드 실패와 분석 실패를 독립적으로
    재시도할 수 있다.
    """

    permission_classes = [IsAuthenticated, IsAdminRole]

    def post(self, request, pk):
        run = get_object_or_404(_scoped_analysis_runs(request.user), pk=pk)

        # 상태 확인과 RUNNING 전환을 하나의 조건부 UPDATE로 묶어 원자적으로 만든다 —
        # 거의 동시에 들어온 두 번째 실행 요청은 이 시점에 이미 막힌다 (SEC-009).
        if not start_run(run):
            return Response(
                {'detail': '이미 실행 중이거나 완료된 분석입니다.'},
                status=status.HTTP_409_CONFLICT,
            )

        run_semgrep(run)
        run.refresh_from_db()
        return Response(AnalysisRunSerializer(run).data)
