"""분석 실행 직렬화 (SFR-007~009, SEC-008)."""

from django.db.models import Count
from rest_framework import serializers

from projects.serializers import UserBriefSerializer

from .models import AnalysisRun
from .services import ZipValidationError, extract_zip_safely, run_sequence


class AnalysisRunSerializer(serializers.ModelSerializer):
    """분석 실행 상태·결과 조회 (SFR-015, SFR-016 전 단계)."""

    created_by = UserBriefSerializer(read_only=True)
    severity_counts = serializers.SerializerMethodField()
    sequence = serializers.SerializerMethodField()

    class Meta:
        model = AnalysisRun
        fields = (
            'id',
            'sequence',
            'project',
            'created_by',
            'original_filename',
            'status',
            'raw_result',
            'error_message',
            'severity_counts',
            'created_at',
            'started_at',
            'finished_at',
        )
        read_only_fields = fields

    def get_severity_counts(self, run):
        """심각도별 결과 건수 (SFR-016).

        목록·상세 뷰는 annotate 값(_with_severity_counts)을 그대로 쓴다 — N+1 방지.
        업로드·실행 직후처럼 annotate 없는 단건 직렬화만 여기서 집계한다(쿼리 1회).
        """
        if hasattr(run, 'num_high'):
            return {'high': run.num_high, 'medium': run.num_medium, 'low': run.num_low}
        counts = dict(run.findings.values_list('severity').annotate(n=Count('id')))
        return {
            'high': counts.get('HIGH', 0),
            'medium': counts.get('MEDIUM', 0),
            'low': counts.get('LOW', 0),
        }

    def get_sequence(self, run):
        """프로젝트 내 회차 — 화면 표시용 ("N번째 분석"), 식별자는 여전히 id.

        목록 뷰는 전체를 들고 있어 자리에서 붙여 준 값(sequence_no)을 쓰고
        (쿼리 0회), 상세·업로드 직후 같은 단건 직렬화만 여기서 계산한다(쿼리 1회).
        severity_counts와 같은 폴백 구조다.
        """
        cached = getattr(run, 'sequence_no', None)
        return cached if cached is not None else run_sequence(run)


class AnalysisRunUploadSerializer(serializers.Serializer):
    """zip 업로드 요청 본문 (SFR-007).

    대상 프로젝트는 본문이 아니라 context로 받는다 — URL의 project_id가 뷰에서
    권한 스코프(IsAdminRole + 프로젝트 존재)를 통과한 뒤에만 여기 도달하므로,
    본문으로 다른 프로젝트를 지정할 경로를 아예 만들지 않는다 (SEC-005).
    """

    file = serializers.FileField()

    def validate_file(self, uploaded_file):
        if not uploaded_file.name.lower().endswith('.zip'):
            raise serializers.ValidationError('zip 파일만 업로드할 수 있습니다.')

        max_size = self.context['max_upload_size']
        if uploaded_file.size > max_size:
            raise serializers.ValidationError(
                f'업로드 용량이 상한({max_size // (1024 * 1024)}MB)을 초과합니다.'
            )
        return uploaded_file

    def create(self, validated_data):
        uploaded_file = validated_data['file']

        run = AnalysisRun.objects.create(
            project=self.context['project'],
            created_by=self.context['request'].user,
            original_filename=uploaded_file.name,
        )

        try:
            extract_zip_safely(uploaded_file, run)
        except ZipValidationError as exc:
            # 압축 해제 검증 실패 — 격리 디렉토리에 아무것도 남지 않으므로
            # 등록해 둔 실행 행도 함께 지워 잘못된 PENDING 기록을 남기지 않는다.
            run.delete()
            raise serializers.ValidationError({'file': [str(exc)]})

        return run
