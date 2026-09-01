"""프로젝트·할당 직렬화 (SFR-004, SFR-005)."""

from django.contrib.auth import get_user_model
from django.db import IntegrityError, transaction
from rest_framework import serializers

from .models import Project, ProjectMember

User = get_user_model()


class UserBriefSerializer(serializers.ModelSerializer):
    """응답에 사람을 표시할 때 쓰는 최소 표현.

    role·is_active 등 권한 정보는 담지 않는다 — 할당 화면에 필요한 최소 정보만
    내보낸다 (불필요한 정보 노출 최소화, SEC-006).
    """

    class Meta:
        model = User
        fields = ('id', 'email', 'name')
        read_only_fields = fields


class ProjectSerializer(serializers.ModelSerializer):
    """프로젝트 등록·조회·수정 (SFR-004)."""

    created_by = UserBriefSerializer(read_only=True)

    class Meta:
        model = Project
        fields = ('id', 'name', 'description', 'created_by', 'created_at', 'updated_at')
        # created_by를 read_only로 둔다 — 본문으로 보낸 값은 무시되고 서버가 request.user로
        # 채우므로 생성자를 위조할 수 없다 (mass assignment 방지, SEC-005).
        read_only_fields = ('id', 'created_by', 'created_at', 'updated_at')


class ProjectMemberSerializer(serializers.ModelSerializer):
    """할당 목록 응답 (SFR-005, 관리자 전용)."""

    user = UserBriefSerializer(read_only=True)
    assigned_by = UserBriefSerializer(read_only=True)

    class Meta:
        model = ProjectMember
        fields = ('id', 'user', 'assigned_by', 'assigned_at')
        read_only_fields = fields


class ProjectMemberCreateSerializer(serializers.Serializer):
    """할당 요청 본문 (SFR-005).

    대상 프로젝트는 본문이 아니라 context로 받는다 — URL의 project_id는 뷰에서
    권한 스코프를 통과한 뒤에만 여기 도달하므로, 본문으로 다른 프로젝트를
    지정할 경로를 아예 만들지 않는다 (SEC-005).
    """

    user_id = serializers.PrimaryKeyRelatedField(
        queryset=User.objects.all(),
        source='user',
    )

    def validate_user_id(self, user):
        project = self.context['project']
        if ProjectMember.objects.filter(project=project, user=user).exists():
            raise serializers.ValidationError('이미 할당된 사용자입니다.')
        return user

    def create(self, validated_data):
        try:
            # UniqueConstraint 위반은 IntegrityError로 올라와 트랜잭션을 오염시키므로
            # savepoint 안에서 실행해 이 작업만 되돌린다.
            with transaction.atomic():
                return ProjectMember.objects.create(
                    project=self.context['project'],
                    user=validated_data['user'],
                    assigned_by=self.context['request'].user,
                )
        except IntegrityError:
            # 동시 요청이 validate를 함께 통과한 경우 — DB 제약이 막은 것을 400으로 되돌린다.
            raise serializers.ValidationError({'user_id': ['이미 할당된 사용자입니다.']})
