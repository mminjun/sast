"""zip 업로드 검증·격리 추출, Semgrep 실행 (SEC-007, SEC-008, SFR-008~009).

뷰는 이 모듈의 함수만 호출한다 — 파일시스템·subprocess를 다루는 코드를
한 곳에 모아 IDOR·경로 검증 지점을 뷰 로직에 흩뿌리지 않는다.
"""

import json
import os
import shutil
import stat
import subprocess
import zipfile
from pathlib import Path

from django.conf import settings
from django.db.models import Q
from django.utils import timezone

from .models import AnalysisRun, AnalysisStatus
from .signals import run_succeeded


def run_sequence(run):
    """프로젝트 안에서 이 실행이 몇 번째인지 — 생성 순서 기준, 1부터.

    화면은 DB 전체 id 대신 이 회차를 보여준다("이 프로젝트의 N번째 분석").
    URL·API 식별자는 그대로 id다. 목록처럼 전체를 이미 들고 있는 곳은
    쿼리 없이 자리에서 계산하고(analysis/views.py), 단건 응답만 이 함수를 쓴다.
    """
    return AnalysisRun.objects.filter(project_id=run.project_id).filter(
        Q(created_at__lt=run.created_at)
        | Q(created_at=run.created_at, pk__lte=run.pk)
    ).count()


class ZipValidationError(Exception):
    """업로드된 zip이 안전하지 않거나 상한을 넘을 때 (SEC-008)."""


def workspace_dir(run):
    """실행 1건의 격리 디렉토리 (SEC-007).

    workspace_id + 고정 루트로 매번 재계산한다 — DB에 저장된 경로 문자열을
    그대로 신뢰해 파일시스템을 조작하지 않는다.
    """
    return Path(settings.ANALYSIS_WORKSPACE_ROOT) / str(run.workspace_id)


def upload_zip_path(run):
    return workspace_dir(run) / 'upload.zip'


def source_dir(run):
    return workspace_dir(run) / 'source'


def _is_unsafe_member(info, dest_root):
    """zip 항목 하나가 안전하지 않은지 판정한다 (Zip Slip 방어, SEC-008)."""
    name = info.filename
    if not name:
        return True

    # 절대경로·드라이브 문자(Windows, 예: "C:/evil") 차단
    if os.path.isabs(name) or ':' in name:
        return True

    # 상위 디렉토리 세그먼트 차단 (Path는 이 환경(Windows)에서 '/'와 '\' 둘 다 구분자로 처리)
    if '..' in Path(name).parts:
        return True

    # 최종 방어선: 추출 목적지가 격리 루트 밖으로 벗어나는지 실제 경로로 확인
    target = (dest_root / name).resolve()
    try:
        target.relative_to(dest_root.resolve())
    except ValueError:
        return True

    # 유닉스 심볼릭 링크 항목(external_attr 상위 16비트가 유닉스 파일 모드) 차단
    mode = info.external_attr >> 16
    if stat.S_ISLNK(mode):
        return True

    return False


def extract_zip_safely(uploaded_file, run):
    """업로드된 zip을 검증 후 run의 격리 디렉토리에 추출한다.

    실패 시 부분 추출을 남기지 않도록, 모든 항목을 먼저 검증하고 나서
    추출한다 — 한 항목이라도 걸리면 아무것도 쓰지 않는다.
    """
    if not zipfile.is_zipfile(uploaded_file):
        raise ZipValidationError('zip 파일이 아닙니다.')

    uploaded_file.seek(0)
    with zipfile.ZipFile(uploaded_file) as zf:
        infolist = zf.infolist()

        if len(infolist) > settings.ANALYSIS_MAX_EXTRACTED_FILES:
            raise ZipValidationError(
                f'압축 해제 파일 개수가 상한({settings.ANALYSIS_MAX_EXTRACTED_FILES}개)을 '
                '초과합니다.'
            )

        # 중앙 디렉토리에 선언된 크기로 빠르게 걸러낸다. 이 값은 조작될 수 있으므로
        # 최종 방어는 아래 실제 추출 루프에서 읽은 바이트 수로 다시 확인한다.
        total_size = sum(info.file_size for info in infolist)
        if total_size > settings.ANALYSIS_MAX_EXTRACTED_SIZE:
            max_mb = settings.ANALYSIS_MAX_EXTRACTED_SIZE // (1024 * 1024)
            raise ZipValidationError(f'압축 해제 후 총 용량이 상한({max_mb}MB)을 초과합니다.')

        dest_root = source_dir(run)

        for info in infolist:
            if info.is_dir():
                continue
            if _is_unsafe_member(info, dest_root):
                raise ZipValidationError(
                    f'허용되지 않는 경로가 포함되어 있습니다: {info.filename}'
                )

        dest_root.mkdir(parents=True, exist_ok=True)
        written_size = 0
        for info in infolist:
            if info.is_dir():
                continue
            target = (dest_root / info.filename).resolve()
            target.parent.mkdir(parents=True, exist_ok=True)
            # info.file_size(중앙 디렉토리 선언값)는 조작될 수 있으므로, 실제로 읽어
            # 쓴 바이트 수를 청크 단위로 누적 확인한다 — 선언값이 아니라 실측값 기준
            # 상한이어야 zip bomb 방어가 실효성이 있다 (SEC-008, secure-review 지적).
            with zf.open(info) as src, open(target, 'wb') as dst:
                while True:
                    chunk = src.read(1024 * 1024)
                    if not chunk:
                        break
                    written_size += len(chunk)
                    if written_size > settings.ANALYSIS_MAX_EXTRACTED_SIZE:
                        dst.close()
                        shutil.rmtree(dest_root, ignore_errors=True)
                        max_mb = settings.ANALYSIS_MAX_EXTRACTED_SIZE // (1024 * 1024)
                        raise ZipValidationError(
                            f'압축 해제 후 총 용량이 상한({max_mb}MB)을 초과합니다.'
                        )
                    dst.write(chunk)


def start_run(run):
    """PENDING/FAILED 상태에서만 RUNNING으로 전환한다 (SEC-009).

    상태 확인과 전환이 한 번의 조건부 UPDATE라 원자적이다 — 같은 run에 대한
    거의 동시 실행 요청 두 건이 모두 통과해 Semgrep이 중복 실행되는 경합을
    막는다 (secure-review 지적). 전환에 성공한 요청만 True를 받는다.
    """
    updated = AnalysisRun.objects.filter(
        pk=run.pk,
        status__in=(AnalysisStatus.PENDING, AnalysisStatus.FAILED),
    ).update(status=AnalysisStatus.RUNNING, started_at=timezone.now())
    if updated:
        run.refresh_from_db()
    return bool(updated)


def run_semgrep(run):
    """격리된 소스 디렉토리에 대해 Semgrep을 동기 실행한다 (SFR-008~009, SEC-009).

    run.status를 직접 갱신·저장한다 — 호출자(뷰)는 결과만 확인하면 된다.
    RUNNING 전환은 start_run()이 이미 원자적으로 마쳤다고 가정한다.
    """
    target = source_dir(run)

    # 분석 대상 파일이 하나도 없으면 Semgrep을 돌리지 않는다. 빈 zip·지원 언어 파일이
    # 없는 zip도 Semgrep은 exit 0을 반환해 SUCCEEDED·0건으로 보이는데, 대상 없는
    # 입력은 유효하지 않은 분석이므로 실패로 기록한다 (TST-008, SFR-015).
    suffixes = settings.ANALYSIS_SCAN_TARGET_SUFFIXES
    if not any(
        p.is_file() and p.suffix.lower() in suffixes
        for p in target.rglob('*')
    ):
        run.status = AnalysisStatus.FAILED
        run.error_message = (
            f'분석 가능한 소스 파일이 없습니다 (지원 확장자: {", ".join(suffixes)}).'
        )
        run.finished_at = timezone.now()
        run.save(update_fields=['status', 'error_message', 'finished_at'])
        return

    try:
        completed = subprocess.run(
            [
                'semgrep',
                'scan',
                f'--config={settings.ANALYSIS_SEMGREP_CONFIG}',
                '--json',
                '--quiet',
                '--metrics=off',  # 잠재적으로 민감한 고객 소스코드를 다루는 도구라
                                  # 기본 익명 사용 지표 전송조차 켜 두지 않는다.
                # 작업 영역은 MEDIA_ROOT 아래이고 .gitignore에 /media/가 있다. Semgrep은
                # 기본적으로 git ignore 규칙을 적용하므로, 이 옵션이 없으면 격리
                # 디렉토리 전체가 스캔 대상에서 빠져 결과가 0건이 된다. 그런데도 종료
                # 코드는 0이라 실행은 성공으로 보인다 (docs/decisions.md 발견 2).
                '--no-git-ignore',
                str(target),
            ],
            capture_output=True,
            text=True,
            # 출력 인코딩을 명시한다. 지정하지 않으면 로케일 기본값(한국어 Windows는
            # cp949)으로 디코딩해, 한글이 든 룰 메시지가 담긴 JSON이 깨진다.
            encoding='utf-8',
            # 자식 프로세스도 UTF-8 모드로 띄운다. Semgrep CLI가 룰 파일을 인코딩
            # 지정 없이 읽어, 이게 없으면 한글 메시지에서 UnicodeDecodeError로
            # 룰 로딩 자체가 실패한다 (docs/decisions.md 발견 1).
            env={**os.environ, 'PYTHONUTF8': '1'},
            timeout=settings.ANALYSIS_SEMGREP_TIMEOUT,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        run.status = AnalysisStatus.FAILED
        run.error_message = (
            f'Semgrep 실행이 {settings.ANALYSIS_SEMGREP_TIMEOUT}초를 초과해 중단되었습니다.'
        )
        run.finished_at = timezone.now()
        run.save(update_fields=['status', 'error_message', 'finished_at'])
        return

    # Semgrep은 findings가 있어도(정상 스캔) exit code 0이다.
    # 0이 아니면 스캔 자체의 실패(설정 오류 등)로 취급한다.
    if completed.returncode != 0:
        run.status = AnalysisStatus.FAILED
        run.error_message = (completed.stderr or '')[:4000] or 'Semgrep 실행이 실패했습니다.'
        run.finished_at = timezone.now()
        run.save(update_fields=['status', 'error_message', 'finished_at'])
        return

    run.raw_result = json.loads(completed.stdout)
    run.status = AnalysisStatus.SUCCEEDED
    run.finished_at = timezone.now()
    run.save(update_fields=['raw_result', 'status', 'finished_at'])

    # 결과가 저장된 뒤에 알린다 — 수신자(catalog)가 raw_result를 읽어 표준화한다.
    # 이 앱은 듣는 쪽이 누구인지 모른다 (analysis/signals.py 참고, QLT-001).
    run_succeeded.send(sender=AnalysisRun, run=run)
