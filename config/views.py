"""프로젝트 수준 뷰 — 프론트 SPA 진입점 (Docker 한 줄 실행, docs/decisions.md 2026-09-07).

React Router가 /projects/3 같은 경로를 브라우저 쪽에서 처리하므로, 서버는 /api·/admin·/static·/assets가
아닌 어떤 경로에도 같은 index.html을 돌려줘야 새로고침·직접 진입이 된다. 정적 자산(/assets/…)은
whitenoise가 미들웨어 단계에서 먼저 서빙하고(settings.WHITENOISE_ROOT), 여기까지 오는 것은 HTML 문서
요청뿐이다.

템플릿 엔진을 거치지 않고 파일을 그대로 읽는다 — Vite 산출물은 Django 템플릿이 아니고, 요청마다 읽어도
1KB 남짓이라 비용이 없으며, 이미지를 새로 배포하면 재기동 없이 새 index가 나간다.
"""

from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound

# dist가 없을 때의 안내. 컨테이너 이미지는 항상 dist를 포함하므로 호스트에서 runserver로 루트에
# 접근했을 때만 보인다 — 개발은 Vite dev 서버(localhost:5173)를 쓴다는 힌트.
_NO_BUILD_HINT = (
    '프론트 빌드(frontend/dist)가 없습니다. 개발 중이면 Vite dev 서버(localhost:5173)를 쓰고, '
    '이 서버에서 직접 보려면 `cd frontend && npm run build` 또는 Docker(docker compose up)로 띄우세요.'
)


def spa_index(request, path=''):
    index = settings.FRONTEND_DIST / 'index.html'
    if not index.is_file():
        return HttpResponseNotFound(_NO_BUILD_HINT, content_type='text/plain; charset=utf-8')
    response = HttpResponse(index.read_bytes(), content_type='text/html; charset=utf-8')
    # 문서는 캐시하지 않는다 — 자산은 해시 파일명으로 장기 캐시되므로 문서만 새로 받으면 새 배포가 반영된다.
    response['Cache-Control'] = 'no-cache'
    return response
