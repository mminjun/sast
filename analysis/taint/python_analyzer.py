"""Python 소스의 taint 분석 — 1단계: 함수 안 (docs/decisions.md 2026-09-06 custom-taint 판단 3·4).

`ast`로 파싱한 뒤 함수마다 문장을 차례로 돌며 환경({접근 경로: Taint})을 흘린다. NodeVisitor를 쓰지 않는
이유: visit가 환경을 돌려주지 않아 분기 병합을 표현할 수 없다. 제어 흐름은 경로 비민감 합집합(may)이다 —
if는 두 갈래를 같은 환경 사본에서 분석해 합치고, 루프는 본문을 LOOP_PASSES번 돌려 루프 전달 오염을 근사하며,
try는 본문·핸들러·else·finally를 합친다. 검사 가드(`if x in ALLOWED:`, `if not re.fullmatch(p, x): raise`,
`if not p.is_relative_to(ROOT): raise`)는 그 뒤의 변수를 깨끗하게 본다(Semgrep by-side-effect와 같은 근사).

포기한 것(문서화): 경로 민감도, 전역 변수, 클로저 변수, *args/**kwargs, 데코레이터 의미, 동적 기능. 중첩
함수·메서드는 각각 독립된 함수로 분석한다(바깥 변수는 보지 않음). 함수 간·클래스 필드는 2·3단계.
"""

import ast

from . import spec
from .state import KIND_INPUT, KIND_PARAM, Summary, Taint, lookup, merge, node, prefer

# 루프 본문을 몇 번 돌려 루프 전달 오염을 근사할지. 고정점 대신 상한 — n번이면 n단계 역방향 체인
# (a = b; b = c; c = 입력)까지 잡고 그보다 긴 체인은 놓친다(상한이 어디든 한계는 남는다). 비용이 사실상 0이고
# 미탐은 오탐과 달리 아무도 모르는 채 지나가므로 2 → 3으로 올렸다 (docs/decisions.md 2026-09-06 custom-taint).
LOOP_PASSES = 3

_SCOPE_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


class Finding:
    """싱크 도달 1건 — kisa_code, 싱크 노드, 거기 닿은 Taint, 스펙의 메시지·CWE."""

    __slots__ = ('kisa_code', 'sink', 'taint', 'message', 'cwe')

    def __init__(self, kisa_code, sink, taint, message, cwe):
        self.kisa_code, self.sink, self.taint, self.message, self.cwe = kisa_code, sink, taint, message, cwe

    @property
    def key(self):
        return (self.kisa_code, self.sink['line'])


def dotted(expr):
    """호출 대상을 점 표기로 (`os.path.join`). Name·Attribute 체인이 아니면 None."""
    if isinstance(expr, ast.Name):
        return expr.id
    if isinstance(expr, ast.Attribute):
        base = dotted(expr.value)
        return f'{base}.{expr.attr}' if base else None
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


class FunctionAnalyzer:
    """함수 하나의 문장을 돌며 싱크 도달을 모은다."""

    def __init__(self, func, lines, rel_path, findings):
        self.func = func
        self.lines = lines
        self.rel_path = rel_path
        self.findings = findings
        self.summary = Summary()
        self.params = [
            arg.arg for arg in (*func.args.posonlyargs, *func.args.args, *func.args.kwonlyargs)
            if arg.arg not in spec.PARAM_SOURCE_EXCLUDE
        ]

    # --- 노드 -------------------------------------------------------------------------
    def node(self, ast_node):
        line = ast_node.lineno
        return node(self.rel_path, line, self.lines[line - 1].strip() if line <= len(self.lines) else '')

    # --- 소스 판정 ---------------------------------------------------------------------
    def _request_source(self, expr):
        """request.<M>.get(...) / request.<M>[...] / request.body / request.get_json(...) 형태인가."""
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

    # --- 표현식의 오염 -------------------------------------------------------------------
    def taint_of(self, expr, env):
        if expr is None or isinstance(expr, ast.Constant):
            return None

        if isinstance(expr, (ast.Name, ast.Attribute, ast.Subscript)):
            # 실제 입력이 매개변수(request)보다 우선 — 경로가 더 구체적이다.
            if self._request_source(expr):
                return Taint(self.node(expr), kind=KIND_INPUT)
            if isinstance(expr, ast.Attribute) and spec.is_sanitizer_attribute(expr.attr):
                return None
            name = dotted(expr)
            if name in spec.SOURCE_NAMES:
                return Taint(self.node(expr), kind=KIND_INPUT)
            path = access_path(expr)
            if path is not None:
                found = lookup(env, path)
                if found is not None:
                    return found
            if isinstance(expr, ast.Subscript):
                return self.taint_of(expr.value, env) or self.taint_of(expr.slice, env)
            if isinstance(expr, ast.Attribute):
                return self.taint_of(expr.value, env)
            return None

        if isinstance(expr, ast.Call):
            callee = dotted(expr.func) or ''
            if callee in spec.SOURCE_CALLS or self._request_source(expr):
                return Taint(self.node(expr), kind=KIND_INPUT)
            if callee and spec.is_sanitizer_call(callee):
                return None
            # 모르는 호출: 인자·대상 객체의 오염이 결과로 전파된다 (Semgrep과 같은 기본).
            candidates = [self.taint_of(a, env) for a in expr.args]
            candidates += [self.taint_of(k.value, env) for k in expr.keywords]
            if isinstance(expr.func, ast.Attribute):
                candidates.append(self.taint_of(expr.func.value, env))
            return self._first(candidates)

        if isinstance(expr, ast.JoinedStr):
            return self._first(
                self.taint_of(v.value if isinstance(v, ast.FormattedValue) else v, env)
                for v in expr.values
            )
        if isinstance(expr, ast.FormattedValue):
            return self.taint_of(expr.value, env)
        if isinstance(expr, ast.BinOp):
            return self._first((self.taint_of(expr.left, env), self.taint_of(expr.right, env)))
        if isinstance(expr, ast.BoolOp):
            return self._first(self.taint_of(v, env) for v in expr.values)
        if isinstance(expr, ast.UnaryOp):
            return self.taint_of(expr.operand, env)
        if isinstance(expr, (ast.List, ast.Tuple, ast.Set)):
            return self._first(self.taint_of(v, env) for v in expr.elts)
        if isinstance(expr, ast.Dict):
            return self._first(self.taint_of(v, env) for v in (*expr.keys, *expr.values) if v is not None)
        if isinstance(expr, ast.IfExp):
            return self._first((self.taint_of(expr.body, env), self.taint_of(expr.orelse, env)))
        if isinstance(expr, (ast.Starred, ast.Await)):
            return self.taint_of(expr.value, env)
        if isinstance(expr, ast.NamedExpr):
            taint = self.taint_of(expr.value, env)
            path = access_path(expr.target)
            if path and taint:
                env[path] = taint
            return taint
        if isinstance(expr, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            # 컴프리헨션: 순회 대상이 오염이면 원소도 오염, 원소식 자체의 오염도 본다(타깃 변수는 바깥 환경으로).
            comp_env = dict(env)
            for gen in expr.generators:
                iter_taint = self.taint_of(gen.iter, env)
                target = access_path(gen.target)
                if iter_taint and target:
                    comp_env[target] = iter_taint
            elts = (expr.key, expr.value) if isinstance(expr, ast.DictComp) else (expr.elt,)
            return self._first(self.taint_of(e, comp_env) for e in elts)
        if isinstance(expr, ast.Compare):
            return None  # 비교 결과(bool)는 값이 아니다
        return None

    @staticmethod
    def _first(candidates):
        best = None
        for taint in candidates:
            if taint is not None:
                best = prefer(best, taint)
                if best.kind == KIND_INPUT:
                    return best
        return best

    # --- 싱크 -------------------------------------------------------------------------
    def check_calls(self, tree, env):
        for call in iter_calls(tree):
            self.check_call(call, env)

    def check_call(self, call, env):
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
            taint = self.taint_of(target, env)
            if taint is None:
                continue
            sink_node = self.node(call)
            self.findings.append(Finding(sink.kisa_code, sink_node, taint, sink.message, sink.cwe))
            if taint.kind == KIND_PARAM:
                self.summary.param_to_sinks.append((taint.source.get('param'), sink.kisa_code, sink_node, taint.steps))

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
            # 매개변수 소스 — 소스 노드는 def 줄(Semgrep 텍스트 출력과 같은 표시). 위치는 2단계 요약용.
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
            for key in [k for k in env if k[:len(path)] == path]:
                del env[key]
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
            taint = self.taint_of(stmt.value, env)
            if taint is not None and taint.kind == KIND_PARAM:
                self.summary.param_to_return[taint.source.get('param')] = taint.steps + (self.node(stmt),)
            return env
        return env


def all_functions(tree):
    """모듈의 모든 함수·메서드·중첩 함수 (각각 독립된 분석 단위)."""
    return [n for n in ast.walk(tree) if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))]


def analyze_module(source, rel_path):
    """소스 텍스트 하나를 분석해 Finding 목록을 돌려준다. 같은 (kisa_code, 싱크 줄)엔 하나(input 우선).

    SyntaxError는 호출자(engine)가 다룬다 — 여기서는 그대로 올린다.
    """
    tree = ast.parse(source)
    lines = source.splitlines()
    findings = []
    for func in all_functions(tree):
        FunctionAnalyzer(func, lines, rel_path, findings).run()

    best = {}
    for finding in findings:
        current = best.get(finding.key)
        if current is None or prefer(current.taint, finding.taint) is not current.taint:
            best[finding.key] = finding
    return sorted(best.values(), key=lambda f: (f.sink['line'], f.kisa_code))
