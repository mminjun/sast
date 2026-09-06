"""오염 상태 표현 (docs/decisions.md 2026-09-06 custom-taint 판단 3).

- AccessPath: 변수·속성 체인·상수 첨자의 튜플 — ('host',), ('self', 'q'), ('d', "['k']"). 환경(env)은
  {AccessPath: Taint}. 읽을 때는 정확한 경로 → 접두사 순으로 찾는다(d가 오염이면 d['k']도).
- Taint: 소스 노드와 지금까지의 경유 노드를 들고 다닌다 — 대입을 지날 때마다 노드를 붙이므로 보고 시점에
  catalog가 쓰는 taint_trace(source/steps/sink) 형식이 그대로 나온다. kind는 'input'(요청·표준입력 등 실제
  외부 입력) 또는 'param'(함수 매개변수). 같은 싱크에 둘 다 닿으면 input을 남기고, 같은 종류면 경유가 긴
  쪽(문맥이 많다)을 남긴다.
- Summary: 2단계(같은 파일 함수 간)의 함수 요약. 매개변수 위치 → 반환, 매개변수 위치 → 함수 안 싱크, 본문 안
  입력 → 반환. shape()는 고정점 판정용 "모양" — 키 집합과 경유 노드 수의 합. 둘 다 유한·단조 증가라 반복이
  반드시 멈춘다(경유 노드 수를 넣지 않으면 경로가 아직 자라는 중에 멈춰 긴 체인의 경로가 잘린다).

노드 = {'path': 상대경로, 'line': 줄, 'code': 줄 텍스트(앞뒤 공백 제거), 선택 'role': source/call/enter/return/sink}.
"""

from dataclasses import dataclass, field, replace

KIND_INPUT = 'input'
KIND_PARAM = 'param'


def node(path, line, code, role=None, method=None):
    result = {'path': path, 'line': line, 'code': code}
    if role:
        result['role'] = role
    if method:
        result['method'] = method  # 필드 대입 노드(role=field)에 대입한 메서드 이름
    return result


@dataclass(frozen=True)
class Taint:
    source: dict
    steps: tuple = ()
    kind: str = KIND_INPUT

    def step(self, new_node, force=False):
        """경유 노드를 붙인 새 Taint. 소스와 같은 줄이거나 이미 있는 줄은 붙이지 않는다(표시 중복 방지).

        force=True면 같은 줄이어도 붙인다 — 필드 대입 노드(role=field)는 `self.q = request.GET.get("q")`처럼
        소스와 같은 줄이어도 "어느 메서드가 대입했나"를 경로에 남겨야 한다(역할이 달라 읽는 데 혼동이 없다).
        """
        if not force:
            if new_node['line'] == self.source['line'] and new_node['path'] == self.source['path']:
                return self
            if any(s['line'] == new_node['line'] and s['path'] == new_node['path'] for s in self.steps):
                return self
        return replace(self, steps=self.steps + (new_node,))


def prefer(current, candidate):
    """같은 싱크에 닿은 두 오염 중 남길 것 — 실제 입력(input)이 매개변수(param)보다 구체적이고, 같은 종류면
    경유가 긴 쪽(호출자까지 이어진 경로)이 문맥이 많다. 다른 경로는 버려진다(paths_count로 개수만 남김)."""
    if current is None:
        return candidate
    if current.kind == KIND_PARAM and candidate.kind == KIND_INPUT:
        return candidate
    if current.kind == candidate.kind and len(candidate.steps) > len(current.steps):
        return candidate
    return current


@dataclass
class Summary:
    """함수 요약 — 같은 파일 함수 간 추적의 단위 (docs/decisions.md 2026-09-06 custom-taint 2단계).

    param_to_return: {매개변수 위치: 경유 노드들} — 그 매개변수의 오염이 반환값에 닿는다.
    param_to_sinks: {(매개변수 위치, kisa_code, 싱크 줄): (싱크 노드, 경유 노드들)} — 함수 안 싱크에 닿는다.
    return_taint: 본문 안의 입력 소스(input()·request 등)가 반환값에 닿을 때 그 Taint.
    """

    param_to_return: dict = field(default_factory=dict)
    param_to_sinks: dict = field(default_factory=dict)
    return_taint: Taint = None

    def shape(self):
        steps = sum(len(v) for v in self.param_to_return.values())
        steps += sum(len(v[1]) for v in self.param_to_sinks.values())
        steps += len(self.return_taint.steps) if self.return_taint is not None else 0
        return (
            frozenset(self.param_to_return), frozenset(self.param_to_sinks),
            self.return_taint is not None, steps,
        )


# 아직 요약이 계산되지 않은 같은 파일 함수의 요약 — 아무것도 전파하지 않는다(낙관적 시작). 고정점 반복이
# 이것을 채워 간다. '모르는 호출'(인자 오염 전파)로 떨어뜨리면 기저 사례 없는 상호 재귀까지 오염된다.
EMPTY_SUMMARY = Summary()


def lookup(env, path):
    """접근 경로의 오염 — 정확한 경로부터 접두사 순으로."""
    for length in range(len(path), 0, -1):
        taint = env.get(path[:length])
        if taint is not None:
            return taint
    return None


def merge(left, right):
    """두 갈래의 환경 합집합(may) — 한쪽이라도 오염이면 오염. 둘 다면 prefer 규칙."""
    merged = dict(left)
    for path, taint in right.items():
        merged[path] = prefer(merged.get(path), taint)
    return merged
