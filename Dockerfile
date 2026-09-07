# Docker 한 줄 실행 (docs/decisions.md 2026-09-07, docs/setup.md "Docker로 띄우기")
#
# 스테이지 1: 프론트 빌드(node). 산출물 frontend/dist만 다음 스테이지로 넘기고 node는 버린다.
# 스테이지 2: Django + Semgrep + gunicorn. web·worker가 같은 이미지를 쓰고 명령만 다르다
#             (docker-compose.yml). Semgrep은 requirements.txt의 pip 의존성이라 함께 설치된다.
#
# 이미지 크기의 대부분은 semgrep-core 바이너리(약 250MB)라 alpine으로 바꿔도 줄지 않고, semgrep wheel이
# glibc(manylinux)라 alpine에서는 아예 안 돈다. 의존성은 전부 wheel이라 gcc 등 빌드 도구가 필요 없다.

FROM node:24-alpine AS frontend
WORKDIR /src
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build


FROM python:3.13-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    # Semgrep 텔레메트리 차단 (SEC-010). 실행 인자 --metrics=off와 이중.
    SEMGREP_SEND_METRICS=off

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

# 소스. .dockerignore가 venv·node_modules·media·logs·.env·.git 등을 뺀다.
COPY . ./
COPY --from=frontend /src/dist ./frontend/dist

# 비루트 사용자 (SEC-007 작업 격리의 연장 — 컨테이너 안에서도 최소 권한).
# media(업로드·실행별 격리 디렉토리)와 logs(접근 로그)는 named volume으로 빠지는데, named volume은
# 첫 마운트 때 이미지 쪽 디렉토리의 소유권을 물려받으므로 여기서 app 소유로 만들어 두면 권한 문제가 없다.
# Semgrep은 $HOME/.semgrep에 설정을 쓰므로 홈 디렉토리가 필요하다.
RUN useradd --create-home --uid 1000 app \
    && mkdir -p /app/media/analysis_runs /app/logs \
    && chown -R app:app /app
USER app

EXPOSE 8000

# 진입 스크립트는 Python이다 — 이 저장소는 Windows에서 core.autocrlf=true로 체크아웃되어 .sh는
# CRLF가 붙은 채 복사되고 `/bin/sh^M`으로 죽는다. Python은 줄 끝을 가리지 않는다.
ENTRYPOINT ["python", "docker/entrypoint.py"]
CMD ["web"]
