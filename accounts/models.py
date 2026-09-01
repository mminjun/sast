"""사용자·역할 모델 (DAR-002, SFR-001, SFR-003)."""

from django.contrib.auth.models import AbstractUser, BaseUserManager
from django.db import models
from django.db.models.functions import Lower


class Role(models.TextChoices):
    """RFP가 요구하는 최소 2역할 (SFR-003)."""

    ADMIN = 'ADMIN', '관리자'
    USER = 'USER', '일반'


class UserManager(BaseUserManager):
    """이메일을 식별자로 쓰는 매니저.

    AbstractUser의 기본 매니저는 username을 요구하므로 교체가 필요하다.
    """

    use_in_migrations = True

    def get_by_natural_key(self, username):
        """로그인 조회를 대소문자 구분 없이 처리한다.

        Django 인증(ModelBackend)과 simplejwt가 모두 이 메서드를 거치므로,
        여기서 한 번만 처리하면 모든 인증 경로에 적용된다.
        저장 시점에도 소문자로 정규화하지만, admin 등 다른 경로로 들어온
        대문자 이메일까지 안전하게 매칭하기 위해 iexact를 쓴다.
        """
        return self.get(**{f'{self.model.USERNAME_FIELD}__iexact': username})

    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError('이메일은 필수입니다.')
        extra_fields.setdefault('role', Role.USER)
        user = self.model(email=self.normalize_email(email), **extra_fields)
        # set_password를 거쳐야 PASSWORD_HASHERS(bcrypt)로 해시된다 — SEC-001.
        # 평문을 password에 직접 넣지 않는다.
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)
        extra_fields.setdefault('role', Role.ADMIN)

        # 호출자가 False를 넘겨 반쪽짜리 superuser가 만들어지는 것을 막는다.
        if extra_fields.get('is_staff') is not True:
            raise ValueError('superuser는 is_staff=True여야 합니다.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('superuser는 is_superuser=True여야 합니다.')

        return self.create_user(email, password, **extra_fields)


class User(AbstractUser):
    """이메일 로그인 사용자 (DAR-002)."""

    # username 대신 email로 로그인한다 (SFR-001).
    username = None
    email = models.EmailField('이메일', unique=True)

    # 표시용 이름. 식별자는 여전히 email이라 유일성·필수 제약을 두지 않는다.
    name = models.CharField('이름', max_length=50, blank=True)

    # 기본값을 일반 사용자로 둔다 — 실수로 만들어진 계정이 관리자 권한을
    # 갖지 않도록 (SEC-003).
    role = models.CharField(
        '역할',
        max_length=10,
        choices=Role.choices,
        default=Role.USER,
    )

    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = []

    objects = UserManager()

    class Meta:
        db_table = 'accounts_user'
        verbose_name = '사용자'
        verbose_name_plural = '사용자'
        constraints = [
            # unique=True의 인덱스는 대소문자를 구분하므로 Kim@x.com과 kim@x.com이
            # 별개 계정으로 공존할 수 있다. 이메일이 로그인 식별자이므로 DB 차원에서
            # 대소문자 무시 유일성을 강제한다 (SFR-001).
            models.UniqueConstraint(
                Lower('email'),
                name='accounts_user_email_ci_unique',
            ),
        ]

    def save(self, *args, **kwargs):
        # 저장 경로가 create_user 하나가 아니므로(admin, 스크립트 등)
        # 모델 저장 지점에서 정규화해 DB 값을 항상 소문자로 유지한다.
        if self.email:
            self.email = self.email.strip().lower()
        return super().save(*args, **kwargs)

    def __str__(self):
        return self.email

    @property
    def is_admin(self):
        """권한 검사용. 항상 DB에 저장된 현재 역할을 본다 (JWT 클레임 아님)."""
        return self.role == Role.ADMIN
