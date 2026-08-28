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
        fields = ('id', 'email', 'role', 'is_active')
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
        fields = ('id', 'email', 'password', 'role', 'is_active')
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
                )
        except IntegrityError:
            raise serializers.ValidationError(
                {'email': ['이미 존재하는 이메일입니다.']}
            )


class UserActiveSerializer(serializers.Serializer):
    """계정 활성 상태 변경 전용 (SEC-003, SEC-004).

    필드가 is_active 하나뿐이라 role·email·password는 본문에 실려 와도
    구조적으로 도달할 수 없다 (mass assignment 방지).
    """

    is_active = serializers.BooleanField(required=True)
