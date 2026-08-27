"""분석 프로젝트·사용자 할당 모델 (DAR-003, DAR-004, SFR-004, SFR-005)."""

from django.conf import settings
from django.db import models


class Project(models.Model):
    """분석 대상 프로젝트 (DAR-003).

    삭제는 비목표(docs/plan.md §5)라 soft-delete 플래그를 두지 않는다.
    """

    name = models.CharField('이름', max_length=200)
    description = models.TextField('설명', blank=True)

    # 생성자는 요청 본문이 아니라 서버가 request.user로 채운다 (projects/views.py).
    # PROTECT — 프로젝트가 참조 중인 사용자가 조용히 사라지지 않게 한다 (DAR-010).
    created_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='created_projects',
        verbose_name='생성자',
    )
    created_at = models.DateTimeField('생성 일시', auto_now_add=True)
    updated_at = models.DateTimeField('수정 일시', auto_now=True)

    # 할당 관계는 ProjectMember를 거친다 — 누가 언제 할당했는지 남기기 위해 through를 쓴다 (DAR-004).
    members = models.ManyToManyField(
        settings.AUTH_USER_MODEL,
        through='ProjectMember',
        # ProjectMember는 User를 두 번(user, assigned_by) 참조하므로 어느 쪽이 '멤버'인지
        # 명시한다. 할당자(assigned_by)는 멤버십이 아니라 감사 기록이다.
        through_fields=('project', 'user'),
        related_name='projects',
        verbose_name='할당된 사용자',
    )

    class Meta:
        db_table = 'projects_project'
        ordering = ('-created_at',)
        verbose_name = '프로젝트'
        verbose_name_plural = '프로젝트'

    def __str__(self):
        return self.name


class ProjectMember(models.Model):
    """사용자-프로젝트 할당 (DAR-004, SFR-005).

    이 테이블의 행이 곧 일반 사용자의 '읽기 권한'이다. 조회 범위 제한(SFR-006)과
    IDOR 방어(SEC-005)는 클라이언트가 보낸 값이 아니라 이 관계를 조회해서 판단한다.

    프로젝트별 세분화 역할(뷰어/편집자)은 두지 않는다 — 쓰기 권한은 전역 User.role이
    결정한다. 권한 계층을 둘로 나누면 검사 지점이 늘어 빠뜨릴 자리가 생긴다 (SFR-003).
    """

    project = models.ForeignKey(
        Project,
        on_delete=models.CASCADE,
        related_name='memberships',
        verbose_name='프로젝트',
    )
    user = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.CASCADE,
        related_name='project_memberships',
        verbose_name='사용자',
    )
    # 할당을 수행한 관리자. 감사 기록이므로 사용자 삭제로 함께 지워지지 않게 PROTECT.
    assigned_by = models.ForeignKey(
        settings.AUTH_USER_MODEL,
        on_delete=models.PROTECT,
        related_name='+',
        verbose_name='할당자',
    )
    assigned_at = models.DateTimeField('할당 일시', auto_now_add=True)

    class Meta:
        db_table = 'projects_project_member'
        ordering = ('-assigned_at',)
        verbose_name = '프로젝트 할당'
        verbose_name_plural = '프로젝트 할당'
        constraints = [
            # 중복 할당 차단 (QLT-005). 시리얼라이저 검증이 1차, 이 제약이 최종 방어선 —
            # 동시 요청이 검증을 함께 통과해도 DB가 막는다.
            models.UniqueConstraint(
                fields=('project', 'user'),
                name='projects_member_unique',
            ),
        ]

    def __str__(self):
        return f'{self.project} ← {self.user}'
