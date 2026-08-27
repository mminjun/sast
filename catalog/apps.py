from django.apps import AppConfig


class CatalogConfig(AppConfig):
    name = 'catalog'

    def ready(self):
        # import 부수효과로 @receiver가 시그널에 연결된다 (catalog/receivers.py).
        # 연결을 앱 로딩 시점에 하지 않으면, 분석 실행이 성공해도 표준화가 돌지 않는다.
        from . import receivers  # noqa: F401
