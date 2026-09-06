"""Python 소스의 taint 분석 — 함수 안 + 같은 파일 함수 간 (docs/decisions.md 2026-09-06 custom-taint 판단 3·4, 2단계).

`ast`로 파싱한 뒤 함수마다 문장을 차례로 돌며 환경({접근 경로: Taint})을 흘린다. NodeVisitor를 쓰지 않는
이유: visit가 환경을 돌려주지 않아 분기 병합을 표현할 수 없다. 제어 흐름은 경로 비민감 합집합(may)이다 —
if는 두 갈래를 같은 환경 사본에서 분석해 합치고, 루프는 본문을 LOOP_PASSES번 돌려 루프 전달 오염을 근사하며,
try는 본문·핸들러·else·finally를 합친다. 검사 가드(`if x in ALLOWED:`, `if not re.fullmatch(p, x): raise`,
`if not p.is_relative_to(ROOT): raise`)는 그 뒤의 변수를 깨끗하게 본다(Semgrep by-side-effect와 같은 근사).

같은 파일 함수 간(2단계): 모듈 최상위 함수의 요약(Summary — 매개변수→반환, 매개변수→싱크, 본문 안 입력→반환)을
빈 요약에서 시작해 모양이 안 바뀔 때까지 반복 계산하고(고정점, 상한 SUMMARY_PASSES), 호출 지점에서 그 요약대로
전파·보고한다. 같은 파일 함수는 이름 규약(validate_ 등)이 아니라 **본문(요약)만** 본다 — 이름이 거짓말하는
헬퍼는 잡히고, 본문이 씻는 헬퍼는 깨끗하다. 요약이 아직 없는 함수는 빈 요약(전파 없음)이라 기저 사례 없는
재귀는 깨끗하게 안정된다. 호출이 정의보다 앞이어도 요약은 모듈 단위로 먼저 계산돼 있다.

포기한 것(문서화): 경로 민감도, 전역·클로저 변수, *args/**kwargs, 데코레이터 의미, 동적 기능, 같은 싱크의 다수
경로 표시(대표 1개 + paths_count). 중첩 함수·메서드는 각각 독립된 함수로 분석하고 모듈 요약에는 넣지 않는다
(호출은 '모르는 호출'로 전파). 클래스 필드는 3단계.
"""

import ast

from . import spec
from .state import (
    EMPTY_SUMMARY, KIND_INPUT, KIND_PARAM, Summary, Taint, lookup, merge, node, prefer,
)

# 루프 본문을 몇 번 돌려 루프 전달 오염을 근사할지. 고정점 대신 상한 — n번이면 n단계 역방향 체인
# (a = b; b = c; c = 입력)까지 잡고 그보다 긴 체인은 놓친다(상한이 어디든 한계는 남는다). 비용이 사실상 0이고
# 미탐은 오탐과 달리 아무도 모르는 채 지나가므로 2 → 3으로 올렸다 (docs/decisions.md 2026-09-06 custom-taint).
LOOP_PASSES = 3
# 함수 요약 고정점 반복의 상한(안전장치). 요약의 모양(키 집합·경유 노드 수)은 유한·단조라 정상 코드는 3~4패스에
# 멈춘다(실측). 한 패스에 체인이 한 단계 번지므로 k단계 반환 체인은 k+1패스에서 완성된다 — 16이면 15단계까지.
SUMMARY_PASSES = 16

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


class Finding:
    """싱크 도달 1건 — kisa_code, 싱크 노드, 거기 닿은 Taint(대표 경로), 스펙의 메시지·CWE, 같은 싱크에 모인 경로 수."""

    __slots__ = ('kisa_code', 'sink', 'taint', 'message', 'cwe', 'paths_count')

    def __init__(self, kisa_code, sink, taint, message, cwe):
        self.kisa_code, self.sink, self.taint, self.message, self.cwe = kisa_code, sink, taint, message, cwe
        self.paths_count = 1

    @property
    def key(self):
        return (self.kisa_code, self.sink['line'])


def dotted(expr):
    """호출 대상을 점 표기로 (`os.path.join`, `conn.cursor().execute`). 체인 안의 호출은 `()`로 표시한다 —
    `$CURSOR.execute(...)`처럼 대상이 호출 결과여도 끝 이름(`*.execute`)으로 싱크가 맞아야 한다(2단계 샘플의
    `conn.cursor().execute(...)`가 첫 판에서 빠졌던 원인). Name·Attribute·Call 체인이 아니면 None."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = dotted(expr.value)
        return f'{base}.{expr.attr}' if base else None
    if isinstance(expr, ast.Call):
        base = dotted(expr.func)
        return f'{base}()' if base else None
    return None


def access_path(expr):
    """변수·속성 체인·상수 첨자를 접근 경로 튜플로. 그 밖(호출 결과 등)은 None."""
    if isinstance(expr, ast.Name):
        return (expr.id,)
    if isinstance(expr, ast.Attribute):
        base = access_path(expr.value)
        return base + (expr.attr,) if base else None
    if isinstance(expr, ast.Subscript):
        base = access_path(expr.value)
        if base is None:
            return None
        key = expr.slice
        return base + (f'[{key.value!r}]' if isinstance(key, ast.Constant) else '[*]',)
    return None


def root_name(expr):
    """접근 경로의 첫 이름 (request.GET.get → 'request')."""
    while isinstance(expr, (ast.Attribute, ast.Subscript, ast.Call)):
        expr = expr.func if isinstance(expr, ast.Call) else expr.value
    return expr.id if isinstance(expr, ast.Name) else None


def iter_calls(tree):
    """문장·식 안의 호출을 순회한다(식 자체가 호출이면 그것도). 중첩 함수·클래스·람다 안은 건너뛴다.

    `with open(p) as f:`처럼 컨텍스트 식·if 조건·for 순회 대상이 호출 그 자체인 경우가 있어 루트를 빠뜨리면
    싱크를 놓친다(자체 저장소 도그푸딩에서 `with open(path)` 6건이 통째로 빠졌던 원인).
    """
    if isinstance(tree, ast.Call):
        yield tree
    stack = [tree]
    while stack:
        current = stack.pop()
        for child in ast.iter_child_nodes(current):
            if isinstance(child, _SCOPE_NODES):
                continue
            if isinstance(child, ast.Call):
                yield child
            stack.append(child)


def param_names(func):
    """소스로 보는 매개변수 이름(정의 순서). self·cls 제외 — 요약의 '매개변수 위치'는 이 목록의 인덱스다."""
    return [
        arg.arg for arg in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)
        if arg.arg not in spec.PARAM_SOURCE_EXCLUDE
    ]


class FunctionAnalyzer:
    """함수 하나의 문장을 돌며 싱크 도달을 모으고, 자기 요약(Summary)을 만든다."""

    def __init__(self, func, lines, rel_path, findings, summaries=None, functions=None):
        self.func = func
        self.lines = lines
        self.rel_path = rel_path
        self.findings = findings
        # 같은 파일 함수의 요약(이전 패스)과 정의. 없으면 함수 간 추적 없이 1단계처럼 돈다.
        self.summaries = summaries if summaries is not None else {}
        self.functions = functions if functions is not None else {}
        self.summary = Summary()
        self.params = param_names(func)

    # --- 노드 -------------------------------------------------------------------------
    def node(self, ast_node, role=None):
        line = ast_node.lineno
        return node(self.rel_path, line, self.lines[line - 1].strip() if line <= len(self.lines) else '', role)

    # --- 소스 판정 ---------------------------------------------------------------------
    def _request_source(self, expr):
        """request.<M>.get(...) / request.<M>.getlist(...) / request.<M>[...] / request.body / request.get_json(...) 형태인가."""
        if root_name(expr) != spec.REQUEST_NAME:
            return False
        if isinstance(expr, ast.Call):
            callee = dotted(expr.func) or ''
            return callee in spec.SOURCE_CALLS or (
                callee.count('.') == 2 and callee.rsplit('.', 1)[-1] in spec.REQUEST_GETTERS
            )
        if isinstance(expr, ast.Subscript):
            return isinstance(expr.value, ast.Attribute) and isinstance(expr.value.value, ast.Name)
        if isinstance(expr, ast.Attribute):
            return expr.attr in spec.REQUEST_PLAIN_ATTRS and isinstance(expr.value, ast.Name)
        return False

    # --- 같은 파일 함수 호출 -------------------------------------------------------------
    def _module_callee(self, call):
        """호출 대상이 모듈 최상위 함수면 그 이름. 점 표기(메서드·모듈 함수)는 해당 없음."""
        name = call.func.id if isinstance(call.func, ast.Name) else None
        return name if name in self.functions else None

    def _mapped_args(self, call, callee_name, env):
        """[(피호출자 매개변수 위치, 인자 오염)] — 위치 인자는 순서, 키워드는 이름. 기본값은 상수로 본다.
        *args/**kwargs 풀기는 범위 밖."""
        names = param_names(self.functions[callee_name])
        mapped = []
        for index, arg in enumerate(call.args):
            if index < len(names) and not isinstance(arg, ast.Starred):
                mapped.append((index, self.taints_of(arg, env)))
        for keyword in call.keywords:
            if keyword.arg in names:
                mapped.append((names.index(keyword.arg), self.taints_of(keyword.value, env)))
        return mapped

    def _through_summary(self, call, callee_name, env):
        """요약이 있는 같은 파일 함수 호출의 결과 오염. 요약이 '깨끗'이면 인자가 오염이어도 None."""
        summary = self.summaries.get(callee_name, EMPTY_SUMMARY)
        callee = self.functions[callee_name]
        flowed_all = []
        for index, taints in self._mapped_args(call, callee_name, env):
            if index not in summary.param_to_return:
                continue
            for taint in taints:
                flowed = taint.step(self.node(call, 'call')).step(self.node(callee, 'enter'))
                for step in summary.param_to_return[index]:
                    flowed = flowed.step(step)
                flowed_all.append(flowed)
        if summary.return_taint is not None:
            # 헬퍼 안의 입력이 반환으로 나온다 — 소스는 헬퍼 안, 그 뒤 호출 줄로 돌아온다.
            flowed_all.append(summary.return_taint.step(self.node(call, 'return')))
        return flowed_all

    def _report_callee_sinks(self, call, callee_name, env):
        """인자의 오염이 같은 파일 함수 안 싱크에 닿으면 그 싱크 위치에 호출자 경로로 보고한다."""
        summary = self.summaries.get(callee_name, EMPTY_SUMMARY)
        if not summary.param_to_sinks:
            return
        callee = self.functions[callee_name]
        for index, taints in self._mapped_args(call, callee_name, env):
            for (p_index, kisa_code, _line), (sink_node, steps) in summary.param_to_sinks.items():
                if p_index != index:
                    continue
                for taint in taints:
                    flowed = taint.step(self.node(call, 'call')).step(self.node(callee, 'enter'))
                    for step in steps:
                        flowed = flowed.step(step)
                    sink = next(s for s in spec.SINKS if s.kisa_code == kisa_code)
                    self.findings.append(Finding(kisa_code, sink_node, flowed, sink.message, sink.cwe))
                    self._record_param_sink(flowed, kisa_code, sink_node)

    def _record_param_sink(self, taint, kisa_code, sink_node):
        if taint.kind == KIND_PARAM and taint.source.get('param') in self.params:
            key = (self.params.index(taint.source['param']), kisa_code, sink_node['line'])
            self.summary.param_to_sinks[key] = (sink_node, taint.steps)

    # --- 표현식의 오염 -------------------------------------------------------------------
    def taint_of(self, expr, env):
        """표현식에 닿은 오염 중 대표 하나(prefer 규칙). 없으면 None."""
        return self._first(self.taints_of(expr, env))

    def taints_of(self, expr, env):
        """표현식에 닿은 오염 전부(부분식의 합집합). 요약을 만들 때 `prefix + host + flag`처럼 여러 매개변수가
        한 반환값·싱크 인자에 섞이면 전부 기록해야 호출자의 어느 인자로도 흐름이 이어진다."""
        if expr is None or isinstance(expr, ast.Constant):
            return []

        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript)):
            # 실제 입력이 매개변수(request)보다 우선 — 경로가 더 구체적이다.
            if self._request_source(expr):
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            if isinstance(expr, ast.Attribute) and spec.is_sanitizer_attribute(expr.attr):
                return []
            name = dotted(expr)
            if name in spec.SOURCE_NAMES:
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            path = access_path(expr)
            if path is not None:
                found = lookup(env, path)
                if found is not None:
                    return [found]
            if isinstance(expr, ast.Subscript):
                return self.taints_of(expr.value, env) + self.taints_of(expr.slice, env)
            if isinstance(expr, ast.Attribute):
                return self.taints_of(expr.value, env)
            return []

        if isinstance(expr, ast.Call):
            callee = dotted(expr.func) or ''
            if callee in spec.SOURCE_CALLS or self._request_source(expr):
                return [Taint(self.node(expr), kind=KIND_INPUT)]
            module_callee = self._module_callee(expr)
            if module_callee is not None:
                # 같은 파일 함수: 본문(요약)만 본다 — 이름 규약(validate_ 등)은 적용하지 않는다.
                return self._through_summary(expr, module_callee, env)
            if callee and spec.is_sanitizer_call(callee):
                return []
            # 모르는 호출: 인자·대상 객체의 오염이 결과로 전파된다 (Semgrep과 같은 기본).
            found = []
            for arg in expr.args:
                found += self.taints_of(arg, env)
            for keyword in expr.keywords:
                found += self.taints_of(keyword.value, env)
            if isinstance(expr.func, ast.Attribute):
                found += self.taints_of(expr.func.value, env)
            return found

        if isinstance(expr, ast.JoinedStr):
            return self._concat(self.taints_of(v, env) for v in expr.values)
        if isinstance(expr, ast.FormattedValue):
            return self.taints_of(expr.value, env)
        if isinstance(expr, ast.BinOp):
            return self.taints_of(expr.left, env) + self.taints_of(expr.right, env)
        if isinstance(expr, ast.BoolOp):
            return self._concat(self.taints_of(v, env) for v in expr.values)
        if isinstance(expr, ast.UnaryOp):
            return self.taints_of(expr.operand, env)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return self._concat(self.taints_of(v, env) for v in expr.elts)
        if isinstance(expr, ast.Dict):
            return self._concat(self.taints_of(v, env) for v in (*expr.keys, *expr.values) if v is not None)
        if isinstance(expr, ast.IfExp):
            return self.taints_of(expr.body, env) + self.taints_of(expr.orelse, env)
        if isinstance(expr, (ast.Starred, ast.Await)):
            return self.taints_of(expr.value, env)
        if isinstance(expr, ast.NamedExpr):
            found = self.taints_of(expr.value, env)
            path = access_path(expr.target)
            if path and found:
                env[path] = self._first(found)
            return found
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # 컴프리헨션: 순회 대상이 오염이면 원소도 오염, 원소식 자체의 오염도 본다(타깃 변수는 바깥 환경으로).
            comp_env = dict(env)
            for gen in expr.generators:
                iter_taint = self.taint_of(gen.iter, env)
                target = access_path(gen.target)
                if iter_taint and target:
                    comp_env[target] = iter_taint
            elts = (expr.key, expr.value) if isinstance(expr, ast.DictComp) else (expr.elt,)
            return self._concat(self.taints_of(e, comp_env) for e in elts)
        return []  # Compare(bool)·Lambda 등은 값이 아니다

    @staticmethod
    def _concat(lists):
        found = []
        for items in lists:
            found += items
        return found

    @staticmethod
    def _first(candidates):
        best = None
        for taint in candidates:
            if taint is not None:
                best = prefer(best, taint)
        return best

    # --- 싱크 -------------------------------------------------------------------------
    def check_calls(self, tree, env):
        for call in iter_calls(tree):
            self.check_call(call, env)

    def check_call(self, call, env):
        module_callee = self._module_callee(call)
        if module_callee is not None:
            self._report_callee_sinks(call, module_callee, env)
            return  # 같은 파일 함수는 요약이 전부다 — 스펙의 싱크로 다시 보지 않는다(로컬 정의가 우선)
        callee = dotted(call.func) or ''
        for sink in spec.sinks_for_call(callee):
            if sink.requires_kw:
                name, value = sink.requires_kw
                if not any(k.arg == name and isinstance(k.value, ast.Constant) and k.value.value == value
                           for k in call.keywords):
                    continue
            target = self._sink_argument(call, sink)
            if target is None:
                continue
            taints = self.taints_of(target, env)
            if not taints:
                continue
            sink_node = self.node(call)
            self.findings.append(Finding(sink.kisa_code, sink_node, self._first(taints), sink.message, sink.cwe))
            for taint in taints:
                self._record_param_sink(taint, sink.kisa_code, sink_node)

    @staticmethod
    def _sink_argument(call, sink):
        if sink.arg == spec.BASE:
            return call.func.value if isinstance(call.func, ast.Attribute) else None
        if isinstance(sink.arg, str) and sink.arg.startswith('kw:'):
            name = sink.arg[3:]
            return next((k.value for k in call.keywords if k.arg == name), None)
        return call.args[sink.arg] if sink.arg < len(call.args) else None

    # --- 문장 순회 ------------------------------------------------------------------------
    def run(self, initial_env=None):
        env = dict(initial_env or {})
        def_node = self.node(self.func)
        for name in self.params:
            # 매개변수 소스 — 소스 노드는 def 줄(Semgrep 텍스트 출력과 같은 표시). 'param'은 요약의 위치 매핑용.
            env[(name,)] = Taint({**def_node, 'param': name}, kind=KIND_PARAM)
        return self.block(self.func.body, env)

    def block(self, stmts, env):
        for stmt in stmts:
            env = self.stmt(stmt, env)
        return env

    def assign(self, target, taint, env, at):
        """대입 대상(이름·속성·첨자·튜플 풀기)에 오염을 기록하거나 지운다."""
        if isinstance(target, (ast.Tuple, ast.List)):
            for elt in target.elts:
                self.assign(elt, taint, env, at)
            return
        if isinstance(target, ast.Starred):
            self.assign(target.value, taint, env, at)
            return
        path = access_path(target)
        if path is None:
            return
        if taint is None:
            self._clear(env, path)
        else:
            env[path] = taint.step(self.node(at))

    def guard_path(self, test):
        """검사 가드가 깨끗하게 만드는 접근 경로. 가드가 아니면 None."""
        if isinstance(test, ast.Compare) and len(test.ops) == 1:
            op = test.ops[0]
            if spec.GUARD_MEMBERSHIP and isinstance(op, (ast.In, ast.NotIn)):
                return access_path(test.left)
            if isinstance(op, (ast.Is, ast.IsNot)) and isinstance(test.left, ast.Call):
                return self._guard_call_path(test.left)
            return None
        if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
            return self.guard_path(test.operand)
        if isinstance(test, ast.Call):
            return self._guard_call_path(test)
        return None

    @staticmethod
    def _guard_call_path(call):
        callee = dotted(call.func) or ''
        head, _, tail = callee.rpartition('.')
        if tail in spec.GUARD_REGEX_FUNCTIONS:
            index = 1 if head == 're' else 0      # re.fullmatch(p, x) / compiled.fullmatch(x)
            return access_path(call.args[index]) if len(call.args) > index else None
        if tail in spec.GUARD_METHODS and isinstance(call.func, ast.Attribute):
            return access_path(call.func.value)
        if callee in spec.GUARD_CALLS:
            index = spec.GUARD_CALLS[callee]
            return access_path(call.args[index]) if len(call.args) > index else None
        return None

    @staticmethod
    def _clear(env, path):
        if path is None:
            return
        for key in [k for k in env if k[:len(path)] == path]:
            del env[key]

    def stmt(self, stmt, env):
        if isinstance(stmt, _SCOPE_NODES):
            return env  # 중첩 정의는 모듈 단위에서 따로 분석한다

        if isinstance(stmt, ast.If):
            self.check_calls(stmt.test, env)
            self.taint_of(stmt.test, env)
            sanitized = self.guard_path(stmt.test)
            body_env = dict(env)
            self._clear(body_env, sanitized)
            body_env = self.block(stmt.body, body_env)
            else_env = self.block(stmt.orelse, dict(env))
            merged = merge(body_env, else_env)
            # early return/raise 검증 뒤엔 깨끗 (Semgrep by-side-effect와 같은 근사 — 분기 모양은 보지 않는다)
            self._clear(merged, sanitized)
            return merged

        if isinstance(stmt, (ast.For, ast.AsyncFor)):
            self.check_calls(stmt.iter, env)
            self.assign(stmt.target, self.taint_of(stmt.iter, env), env, stmt)
            for _ in range(LOOP_PASSES):
                env = merge(self.block(stmt.body, dict(env)), env)
            return merge(self.block(stmt.orelse, dict(env)), env)

        if isinstance(stmt, ast.While):
            for _ in range(LOOP_PASSES):
                self.check_calls(stmt.test, env)
                env = merge(self.block(stmt.body, dict(env)), env)
            return merge(self.block(stmt.orelse, dict(env)), env)

        if isinstance(stmt, ast.Try):
            merged = self.block(stmt.body, dict(env))
            for handler in stmt.handlers:
                merged = merge(self.block(handler.body, dict(env)), merged)
            merged = self.block(stmt.orelse, merged)
            return self.block(stmt.finalbody, merged)

        if isinstance(stmt, (ast.With, ast.AsyncWith)):
            for item in stmt.items:
                self.check_calls(item.context_expr, env)
                if item.optional_vars is not None:
                    self.assign(item.optional_vars, self.taint_of(item.context_expr, env), env, stmt)
            return self.block(stmt.body, env)

        if isinstance(stmt, ast.Match):
            self.check_calls(stmt.subject, env)
            merged = None
            for case in stmt.cases:
                case_env = self.block(case.body, dict(env))
                merged = case_env if merged is None else merge(merged, case_env)
            return merge(merged, env) if merged is not None else env

        # --- 단순 문장: 안의 호출을 먼저 싱크로 검사한 뒤 대입을 반영한다 ---
        self.check_calls(stmt, env)

        if isinstance(stmt, ast.Assign):
            taint = self.taint_of(stmt.value, env)
            for target in stmt.targets:
                self.assign(target, taint, env, stmt)
            return env
        if isinstance(stmt, ast.AnnAssign):
            if stmt.value is not None:
                self.assign(stmt.target, self.taint_of(stmt.value, env), env, stmt)
            return env
        if isinstance(stmt, ast.AugAssign):
            path = access_path(stmt.target)
            taint = self.taint_of(stmt.value, env) or (lookup(env, path) if path else None)
            if path and taint:
                env[path] = taint.step(self.node(stmt))
            return env
        if isinstance(stmt, ast.Delete):
            for target in stmt.targets:
                self._clear(env, access_path(target))
            return env
        if isinstance(stmt, ast.Return):
            returned = self.node(stmt, 'return')
            for taint in self.taints_of(stmt.value, env):
                if taint.kind == KIND_PARAM and taint.source.get('param') in self.params:
                    index = self.params.index(taint.source['param'])
                    self.summary.param_to_return.setdefault(index, taint.steps + (returned,))
                elif taint.kind == KIND_INPUT:
                    self.summary.return_taint = prefer(self.summary.return_taint, taint.step(returned))
            return env
        return env


def module_functions(tree):
    """모듈 최상위 함수 — 같은 이름이면 마지막 정의(임포트 시점의 Python 의미와 같다)."""
    return {n.name: n for n in tree.body if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))}


def all_functions(tree):
    """모듈의 모든 함수·메서드·중첩 함수 (각각 독립된 분석 단위)."""
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def _longer(current, candidate):
    """(노드, 경유) 쌍 중 경유가 긴 쪽 — 요약을 패스마다 단조 증가시키는 병합 규칙."""
    if current is None:
        return candidate
    return candidate if len(candidate[1]) > len(current[1]) else current


def merge_summaries(previous, fresh):
    """이전 패스의 요약과 새 요약을 합쳐 단조 증가하게 만든다.

    키는 합집합, 경유 노드는 긴 쪽을 남긴다. 이렇게 해야 고정점이 보장된다 — 새 요약만 쓰면 상호 재귀 함수에서
    대표 경로가 패스마다 다른 것으로 바뀌어(경유 5개 ↔ 8개) 모양이 영원히 진동한다(Django `db/models/sql/query.py`의
    `rename_prefix_from_q`/`get_child_with_renamed_prefix`에서 실측 — 상한 16에 닿았다). 경유 노드는 줄 단위로
    중복 제거되므로 길이는 함수의 줄 수로 유한하고, 키 집합도 유한하다 → 반드시 안정된다.
    """
    if previous is None:
        return fresh
    merged = Summary()
    for index in set(previous.param_to_return) | set(fresh.param_to_return):
        a, b = previous.param_to_return.get(index), fresh.param_to_return.get(index)
        merged.param_to_return[index] = a if b is None else b if a is None else (b if len(b) > len(a) else a)
    for key in set(previous.param_to_sinks) | set(fresh.param_to_sinks):
        merged.param_to_sinks[key] = _longer(previous.param_to_sinks.get(key), fresh.param_to_sinks.get(key))
    merged.return_taint = prefer(previous.return_taint, fresh.return_taint) if fresh.return_taint else previous.return_taint
    return merged


def compute_summaries(functions, lines, rel_path):
    """모듈 함수 요약의 고정점. 반환: (요약, 반복 횟수). 상한 SUMMARY_PASSES는 안전장치일 뿐이다."""
    summaries = {}
    passes = 0
    for passes in range(1, SUMMARY_PASSES + 1):
        fresh = {}
        for name, func in functions.items():
            analyzer = FunctionAnalyzer(func, lines, rel_path, [], summaries, functions)
            analyzer.run()
            fresh[name] = merge_summaries(summaries.get(name), analyzer.summary)
        shapes_before = {name: summary.shape() for name, summary in summaries.items()}
        shapes_after = {name: summary.shape() for name, summary in fresh.items()}
        summaries = fresh
        if shapes_after == shapes_before:
            break
    return summaries, passes


def analyze_module(source, rel_path, stats=None):
    """소스 텍스트 하나를 분석해 Finding 목록을 돌려준다. 같은 (kisa_code, 싱크 줄)엔 하나(prefer 규칙, paths_count에
    후보 수). stats(dict)를 주면 'summary_passes'(최대 반복 횟수)를 갱신한다. SyntaxError는 호출자(engine)가 다룬다."""
    tree = ast.parse(source)
    lines = source.splitlines()
    functions = module_functions(tree)
    summaries, passes = compute_summaries(functions, lines, rel_path)
    if stats is not None:
        stats['summary_passes'] = max(stats.get('summary_passes', 0), passes)

    findings = []
    for func in all_functions(tree):
        FunctionAnalyzer(func, lines, rel_path, findings, summaries, functions).run()

    best = {}
    for finding in findings:
        current = best.get(finding.key)
        if current is None:
            best[finding.key] = finding
            continue
        current.paths_count += 1
        if prefer(current.taint, finding.taint) is not current.taint:
            finding.paths_count = current.paths_count
            best[finding.key] = finding
    return sorted(best.values(), key=lambda f: (f.sink['line'], f.kisa_code))
