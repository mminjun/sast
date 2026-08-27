"""분석 실행 시그널 (QLT-001).

catalog 앱은 AnalysisRun을 읽어야 하므로 catalog→analysis 의존은 피할 수 없다.
여기에 analysis→catalog 직접 호출까지 더하면 두 앱이 서로를 import하는 순환 의존이
된다. analysis는 "실행이 끝났다"만 알리고, 그 결과로 무엇을 할지는 듣는 쪽이 정한다 —
analysis는 catalog의 존재를 몰라도 된다.
"""

from django.dispatch import Signal

# 분석 실행이 성공적으로 끝나 raw_result가 저장된 직후 발신된다.
# 수신자에게 keyword 인자로 run(AnalysisRun)이 전달된다.
# 실패로 끝난 실행에서는 발신하지 않는다 — 표준화할 결과가 없다.
run_succeeded = Signal()
