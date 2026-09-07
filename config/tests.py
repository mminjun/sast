"""프론트 SPA 진입점 (config/views.py spa_index — Docker 한 줄 실행, docs/decisions.md 2026-09-07)."""

import tempfile
from pathlib import Path

from django.test import SimpleTestCase, override_settings


class SpaIndexTests(SimpleTestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.dist = Path(self.tmp.name)
        (self.dist / 'index.html').write_text('<!doctype html><div id="root"></div>', encoding='utf-8')

    def test_root_and_client_routes_return_index(self):
        with override_settings(FRONTEND_DIST=self.dist):
            for url in ('/', '/projects/3', '/projects/3/runs/7/compare', '/login'):
                with self.subTest(url=url):
                    res = self.client.get(url)
                    self.assertEqual(res.status_code, 200)
                    self.assertIn('<div id="root">', res.content.decode())
                    self.assertEqual(res['Cache-Control'], 'no-cache')

    def test_api_and_reserved_prefixes_are_not_swallowed(self):
        # 없는 API 경로는 index가 아니라 404여야 프론트의 오류 처리가 맞다.
        with override_settings(FRONTEND_DIST=self.dist):
            for url in ('/api/nope/', '/static/nope.css', '/assets/nope.js'):
                with self.subTest(url=url):
                    self.assertEqual(self.client.get(url).status_code, 404)

    def test_missing_build_gives_hint_not_500(self):
        with override_settings(FRONTEND_DIST=self.dist / 'absent'):
            res = self.client.get('/projects/3')
        self.assertEqual(res.status_code, 404)
        self.assertIn('npm run build', res.content.decode())
