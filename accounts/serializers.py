"""사용자 직렬화 (SFR-001)."""

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
