"""자체 분석(도그푸딩)용 zip 생성 — git이 추적하는 파일만 담는다.

사용법 (저장소 루트에서):
    venv\\Scripts\\python scripts\\make_selfscan_zip.py            # sast-selfscan-YYYYMMDD.zip
    venv\\Scripts\\python scripts\\make_selfscan_zip.py out.zip    # 경로 지정

왜 git ls-files인가: 2026-09-05 도그푸딩 zip을 손으로 만들다 `.env`(DB 비밀번호·SECRET_KEY)가
들어가 서버 작업 영역(media/analysis_runs/…/source/)에 4개 실행분이 복사됐다(9/6 삭제).
.gitignore가 이미 `.env`·`logs/`·`media/`·`venv/`를 제외하고 있으므로 "커밋되는 파일 = 스캔에
넣어도 되는 파일"로 두면 제외 목록을 따로 관리하지 않아도 된다. 그래도 사고 재발을 막기 위해
아래 DENY 목록으로 한 번 더 거른다(추적 여부와 무관하게 절대 넣지 않는 이름).

분석 제외(catalog/samples 등)는 여기서 빼지 않는다 — 그건 프로젝트의 '분석 제외 경로'
설정이 담당하고, zip에는 들어가되 스캔에서만 빠져야 "제외가 동작한다"를 확인할 수 있다.
"""

import fnmatch
import subprocess
import sys
import zipfile
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# 추적 여부와 무관하게 절대 넣지 않는다 (경로의 어느 조각이든 매칭).
DENY = ('.env', '.env.*', '*.log', '*.pem', '*.key', 'logs', 'media', 'venv', 'node_modules', 'dist')
ALLOW_EVEN_IF_DENIED = ('.env.example',)


def is_denied(rel_posix):
    parts = rel_posix.split('/')
    if parts[-1] in ALLOW_EVEN_IF_DENIED:
        return False
    return any(fnmatch.fnmatchcase(part, pat) for part in parts for pat in DENY)


def tracked_files():
    out = subprocess.run(
        ['git', 'ls-files', '-z'], cwd=ROOT, check=True, capture_output=True,
    ).stdout.decode('utf-8')
    return [p for p in out.split('\0') if p]


def main(argv):
    out_path = Path(argv[1]) if len(argv) > 1 else ROOT / f'sast-selfscan-{date.today():%Y%m%d}.zip'
    if is_denied(out_path.name) or out_path.suffix != '.zip':
        sys.exit(f'출력 파일명이 올바르지 않습니다: {out_path.name}')

    files = tracked_files()
    included, denied = [], []
    for rel in files:
        (denied if is_denied(rel) else included).append(rel)

    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED) as zf:
        for rel in included:
            src = ROOT / rel
            if src.is_file():  # 삭제됐지만 아직 스테이징 안 된 파일은 건너뛴다
                zf.write(src, rel)

    print(f'{out_path.name}: {len(included)}개 파일 (git 추적 {len(files)}개, DENY로 제외 {len(denied)}개)')
    for rel in denied:
        print(f'  제외: {rel}')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))
