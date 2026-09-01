"""사용자 직렬화 (SFR-001, SEC-003)."""

from django.contrib.auth import password_validation
from django.core.exceptions import ValidationError as DjangoValidationError
from django.db import IntegrityError, transaction
from rest_framework import serializers

from .models import User


class UserSerializer(serializers.ModelSerializer):
    """응답용 사용자 표현.

    password는 필드에 포함하지 않는다 — 해시라도 응답에 실리면
    오프라인 크래킹의 출발점이 된다 (SEC-001, SEC-006).
    """

    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'role', 'is_active')
        read_only_fields = fields


class AssignedProjectSerializer(serializers.Serializer):
    """할당 프로젝트 요약 — 관리 화면 표시용 최소 필드 (SEC-006)."""

    id = serializers.IntegerField(read_only=True)
    name = serializers.CharField(read_only=True)


class UserListSerializer(UserSerializer):
    """관리자용 목록 전용 — 할당 프로젝트 목록을 함께 내려준다 (읽기 전용).

    MeView·생성/수정 응답에는 싣지 않는다 — 목록 화면에서만 쓰는 정보라
    다른 응답 경로의 쿼리·노출 범위를 늘리지 않는다.
    """

    # Project.members의 related_name='projects' — 할당(ProjectMember) 기준이다.
    projects = AssignedProjectSerializer(many=True, read_only=True)

    # 뷰의 annotate가 채운다 — PROTECT 참조(활동 이력)가 있으면 삭제가 409로
    # 거부되므로, UI가 삭제 버튼을 미리 비활성화할 수 있게 내려준다.
    has_history = serializers.BooleanField(read_only=True)

    class Meta(UserSerializer.Meta):
        fields = UserSerializer.Meta.fields + ('projects', 'has_history')
        read_only_fields = fields


class UserCreateSerializer(serializers.ModelSerializer):
    """관리자용 계정 생성 (SEC-003, SEC-001).

    role·is_active는 read_only라 본문에 실려 와도 쓰기 경로가 없다 —
    생성 계정의 역할은 서버(create_user의 기본값 USER)가 확정한다.
    """

    # 상한 없는 비밀번호를 받을 이유가 없다 — 요청 크기 상한과 별개로
    # 필드 수준에서 제한한다 (secure-review 지적).
    password = serializers.CharField(write_only=True, max_length=128)

    class Meta:
        model = User
        fields = ('id', 'email', 'name', 'password', 'role', 'is_active')
        read_only_fields = ('id', 'role', 'is_active')

    def validate_email(self, value):
        # 모델의 unique=True 검증은 대소문자를 구분해서, DB의 Lower('email')
        # 제약에 걸릴 중복(Kim@x.com vs kim@x.com)을 여기서 먼저 걸러낸다.
        # 관리자 전용 API라 중복 응답이 계정 존재를 노출해도 무해하다.
        if User.objects.filter(email__iexact=value.strip()).exists():
            raise serializers.ValidationError('이미 존재하는 이메일입니다.')
        return value

    def validate(self, attrs):
        # AUTH_PASSWORD_VALIDATORS는 DRF가 자동 적용하지 않는다.
        # 미저장 인스턴스를 넘겨 이메일 유사성 검증까지 동작시킨다 (SEC-001).
        try:
            password_validation.validate_password(
                attrs['password'], user=User(email=attrs['email'])
            )
        except DjangoValidationError as exc:
            raise serializers.ValidationError({'password': exc.messages})
        return attrs

    def create(self, validated_data):
        # iexact 검증과 저장 사이의 경합은 DB의 CI 유일 제약이 최종 방어 —
        # IntegrityError를 savepoint 안에서 400으로 변환한다 (QLT-005).
        try:
            with transaction.atomic():
                # create_user 경유라야 set_password(bcrypt)가 적용된다 (SEC-001).
                return User.objects.create_user(
                    email=validated_data['email'],
                    password=validated_data['password'],
                    name=validated_data.get('name', ''),
                )
        except IntegrityError:
            raise serializers.ValidationError(
                {'email': ['이미 존재하는 이메일입니다.']}
            )


class UserUpdateSerializer(serializers.Serializer):
    """계정 수정 전용 — 활성 상태 토글, 표시 이름 (SEC-003, SEC-004).

    필드를 is_active·name으로 한정해 role·email·password는 본문에 실려 와도
    구조적으로 도달할 수 없다 (mass assignment 방지).
    """

    is_active = serializers.BooleanField(required=False)
    name = serializers.CharField(required=False, allow_blank=True, max_length=50)

    def validate(self, attrs):
        if not attrs:
            raise serializers.ValidationError('변경할 필드(is_active, name)가 없습니다.')
        return attrs
