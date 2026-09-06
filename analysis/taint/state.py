"""오염 상태 표현 (docs/decisions.md 2026-09-06 custom-taint 판단 3).

- AccessPath: 변수·속성 체인·상수 첨자의 튜플 — ('host',), ('self', 'q'), ('d', "['k']"). 환경(env)은
  {AccessPath: Taint}. 읽을 때는 정확한 경로 → 접두사 순으로 찾는다(d가 오염이면 d['k']도).
- Taint: 소스 노드와 지금까지의 경유 노드를 들고 다닌다 — 대입을 지날 때마다 노드를 붙이므로 보고 시점에
  catalog가 쓰는 taint_trace(source/steps/sink) 형식이 그대로 나온다. kind는 'input'(요청·표준입력 등 실제
  외부 입력) 또는 'param'(함수 매개변수). 같은 싱크에 둘 다 닿으면 input을 남긴다(경로가 더 구체적).
- Summary: 2단계(함수 간)의 함수 요약 자리. 1단계에서는 비어 있다.

노드 = {'path': 상대경로, 'line': 줄, 'code': 줄 텍스트(앞뒤 공백 제거)}.
"""

from dataclasses import dataclass, field, replace

KIND_INPUT = 'input'
KIND_PARAM = 'param'


def node(path, line, code):
    return {'path': path, 'line': line, 'code': code}


@dataclass(frozen=True)
class Taint:
    source: dict
    steps: tuple = ()
    kind: str = KIND_INPUT

    def step(self, new_node):
        """경유 노드를 붙인 새 Taint. 소스와 같은 줄이거나 이미 있는 줄은 붙이지 않는다(표시 중복 방지)."""
        if new_node['line'] == self.source['line'] and new_node['path'] == self.source['path']:
            return self
        if any(s['line'] == new_node['line'] and s['path'] == new_node['path'] for s in self.steps):
            return self
        return replace(self, steps=self.steps + (new_node,))


def prefer(current, candidate):
    """같은 싱크에 닿은 두 오염 중 남길 것 — 실제 입력(input)이 매개변수(param)보다 구체적이다."""
    if current is None:
        return candidate
    if current.kind == KIND_PARAM and candidate.kind == KIND_INPUT:
        return candidate
    return current


@dataclass
class Summary:
    """함수 요약 — 2단계(같은 파일 함수 간 추적)에서 채운다.

    param_to_return: {매개변수 위치: 경유 노드들} — 그 매개변수의 오염이 반환값에 닿는다.
    param_to_sinks: [(매개변수 위치, kisa_code, 싱크 노드, 경유 노드들)] — 그 매개변수가 함수 안 싱크에 닿는다.
    """

    param_to_return: dict = field(default_factory=dict)
    param_to_sinks: list = field(default_factory=list)


def lookup(env, path):
    """접근 경로의 오염 — 정확한 경로부터 접두사 순으로."""
    for length in range(len(path), 0, -1):
        taint = env.get(path[:length])
        if taint is not None:
            return taint
    return None


def merge(left, right):
    """두 갈래의 환경 합집합(may) — 한쪽이라도 오염이면 오염. 둘 다면 input 우선."""
    merged = dict(left)
    for path, taint in right.items():
        merged[path] = prefer(merged.get(path), taint)
    return merged
