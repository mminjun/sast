"""분석 실행 모델 (DAR-005, SFR-008, SFR-015)."""

import uuid

from django.conf import settings
from django.db import models

from projects.models import Project


class AnalysisStatus(models.TextChoices):
    """분석 실행 상태 (SFR-015)."""

    PENDING = 'PENDING', '대기'
    RUNNING = 'RUNNING', '실행중'
    SUCCEEDED = 'SUCCEEDED', '완료'
    FAILED = 'FAILED', '실패'


class AnalysisRun(models.Model):
    """zip 업로드 1건 = 분석 실행 1건 (DAR-005).

    격리 디렉토리 이름은 PK가 아니라 workspace_id(UUID)를 쓴다 — 순차 ID를
    파일시스템 경로에 노출하지 않기 위해서다 (SEC-007). 실제 경로는 저장된
    문자열이 아니라 workspace_id + 고정 루트(settings.ANALYSIS_WORKSPACE_ROOT)로
    매번 재계산한다 — analysis/services.py: AnalysisRun.workspace_dir 참고.
    """

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='analysis_runs',
        verbose_name='프로젝트',
    )
    # 실행자는 요청 본문이 아니라 서버가 request.user로 채운다 (analysis/views.py).
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='analysis_runs',
        verbose_name='실행자',
    )
    workspace_id = models.UUIDField(
        '작업 영역 ID',
        default=uuid.uuid4,
        editable=False,
        unique=True,
    )
    original_filename = models.CharField('원본 파일명', max_length=255)
    status = models.CharField(
        '상태',
        max_length=10,
        choices=AnalysisStatus.choices,
        default=AnalysisStatus.PENDING,
    )
    # Semgrep --json 원본 출력. 표준화(KISA 49개 매핑)는 catalog 앱의 책임 —
    # 여기서는 있는 그대로 보관만 한다 (SFR-014, DAR-006은 이 앱 범위 밖).
    raw_result = models.JSONField('분석 결과(원본)', null=True, blank=True)
    error_message = models.TextField('오류 메시지', blank=True)

    created_at = models.DateTimeField('생성 일시', auto_now_add=True)
    started_at = models.DateTimeField('실행 시작 일시', null=True, blank=True)
    finished_at = models.DateTimeField('종료 일시', null=True, blank=True)

    class Meta:
        db_table = 'analysis_run'
        ordering = ('-created_at',)
        verbose_name = '분석 실행'
        verbose_name_plural = '분석 실행'

    def __str__(self):
        return f'{self.project} [{self.status}] {self.workspace_id}'
