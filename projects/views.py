"""프로젝트 관리·사용자 할당 뷰 (SFR-004~006, SEC-003~006).

접근 통제의 핵심은 get_queryset()이다. 권한을 뷰의 분기문이 아니라 queryset에 걸어,
클라이언트가 URL에 넣은 project_id로는 권한 밖 행에 도달할 수 없게 한다 (IDOR 방어, SEC-005).
"""

from django.shortcuts import get_object_or_404
from rest_framework import mixins, status, viewsets
from rest_framework.decorators import action
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response

from accounts.permissions import IsAdminRole

from .models import Project
from .serializers import (
    ProjectMemberCreateSerializer,
    ProjectMemberSerializer,
    ProjectSerializer,
)


class ProjectViewSet(mixins.CreateModelMixin,
                     mixins.ListModelMixin,
                     mixins.RetrieveModelMixin,
                     mixins.UpdateModelMixin,
                     viewsets.GenericViewSet):
    """프로젝트 등록·조회·수정 + 사용자 할당 (SFR-004, SFR-005).

    ModelViewSet 대신 mixin을 조합한다 — DestroyModelMixin을 빼면 삭제 라우트가
    405가 아니라 아예 생성되지 않는다. 프로젝트 삭제는 비목표(docs/plan.md §5).
    """

    serializer_class = ProjectSerializer
    # PUT(전체 교체)은 받지 않는다 — 일부 필드만 보냈을 때 나머지가 지워지는 사고를 막는다.
    http_method_names = ['get', 'post', 'patch', 'delete', 'head', 'options']
    # pk는 BigAutoField라 숫자만 온다. 숫자가 아닌 값이 오면 정수 캐스팅에서 500이
    # 나기 전에 URL 매칭 단계에서 걸러 404로 떨어뜨린다 (member_detail 액션과 동일한 원칙).
    lookup_value_regex = r'\d+'

    def get_queryset(self):
        """일반 사용자는 할당된 프로젝트만 본다 (SFR-006, SEC-005).

        권한을 queryset에 거는 이유: 상세·수정·할당이 모두 get_object()를 거치므로
        URL의 pk가 조작돼도 스코프 밖 행에는 도달할 방법이 없다. 빠뜨릴 수 있는
        if문 대신 조회 자체를 제한한다.

        스코프 밖 pk는 404가 되므로, 권한 없는 프로젝트와 존재하지 않는 프로젝트의
        응답이 같아진다 — 응답 차이로 존재를 알아낼 수 없다 (SEC-006).
        """
        queryset = Project.objects.select_related('created_by')

        # 역할은 JWT 클레임이 아니라 DB의 현재 값으로 판단한다 (accounts/models.py: User.is_admin).
        if self.request.user.is_admin:
            return queryset

        # 클라이언트가 보낸 값이 아니라 DB의 할당 관계로 재검증한다 (SEC-005).
        # UniqueConstraint(project, user) 덕분에 조인 결과가 중복되지 않아 distinct()가 필요 없다.
        return queryset.filter(memberships__user=self.request.user)

    def get_permissions(self):
        """읽기 두 개만 인증으로 열고, 나머지는 전부 관리자 (SEC-003, SEC-004).

        허용 목록 방식이라 나중에 action을 추가하고 권한 지정을 잊어도
        관리자 전용으로 닫히는 방향으로 실패한다 (settings의 기본 권한과 같은 원칙).
        """
        if self.action in ('list', 'retrieve'):
            return [IsAuthenticated()]
        return [IsAuthenticated(), IsAdminRole()]

    def perform_create(self, serializer):
        # 생성자는 본문이 아니라 인증된 사용자로 채운다 (SEC-005).
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['get', 'post'], url_path='members')
    def members(self, request, pk=None):
        """할당 목록 조회·추가 (SFR-005, 관리자 전용).

        프로젝트는 반드시 get_object()로 얻는다 — 중첩 자원에서 부모의 권한 검증을
        건너뛰는 것이 IDOR의 전형적인 경로다.

        일반 사용자에게는 자기 프로젝트여도 403이다. 다른 참여자 명단을 볼 이유가
        없고, 응답이 project_id에 따라 갈리지 않으므로 존재도 새지 않는다 (SEC-006).
        """
        project = self.get_object()

        if request.method == 'POST':
            serializer = ProjectMemberCreateSerializer(
                data=request.data,
                context={'project': project, 'request': request},
            )
            serializer.is_valid(raise_exception=True)
            membership = serializer.save()
            return Response(
                ProjectMemberSerializer(membership).data,
                status=status.HTTP_201_CREATED,
            )

        memberships = project.memberships.select_related('user', 'assigned_by')
        return Response(ProjectMemberSerializer(memberships, many=True).data)

    @action(detail=True, methods=['delete'], url_path=r'members/(?P<user_id>\d+)')
    def member_detail(self, request, pk=None, user_id=None):
        """할당 해제 (SFR-005, 관리자 전용).

        프로젝트는 스코프된 get_object()로, 할당 행은 그 프로젝트에 한정해서 찾는다 —
        user_id만으로 다른 프로젝트의 할당을 지울 수 없다 (SEC-005).
        """
        project = self.get_object()
        membership = get_object_or_404(project.memberships, user_id=user_id)
        membership.delete()
        return Response(status=status.HTTP_204_NO_CONTENT)
