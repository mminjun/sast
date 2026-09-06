import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import CodeSnippet from '../components/CodeSnippet.jsx';
import FindingStatusBadge, { FINDING_STATUS_LABELS } from '../components/FindingStatusBadge.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { formatDateTime, formatUser } from '../utils/format.js';
import {
  POLL_INTERVAL_MS, QUEUED_STALE_HINT, isInProgress, isQueuedTooLong,
} from '../utils/runStatus.js';

const PAGE_SIZE = 50; // 서버 FindingPagination.page_size와 동일
const FINDING_STATUSES = Object.keys(FINDING_STATUS_LABELS); // OPEN, FALSE_POSITIVE, ACCEPTED

/** 오염 경로 — 소스 → 중간 변수 → 싱크. extra.taint_trace 형식은 catalog/services.py
 *  (자체 taint 구현도 같은 형식). 노드마다 path가 있어 파일이 달라져도 표시할 수 있다. */
function TaintTrace({ trace }) {
  const nodes = [
    { role: '소스', ...trace.source },
    ...trace.steps.map((step) => ({ role: '경유', ...step })),
    { role: '싱크', ...trace.sink },
  ];
  const samePath = nodes.every((n) => n.path === trace.sink.path);
  return (
    <ol className="taint-trace">
      {nodes.map((n, index) => (
        <li key={`${n.path}:${n.line}:${index}`}>
          <span className="taint-role">{n.role}</span>
          <span className="mono small muted">
            {samePath ? '' : `${n.path}:`}{n.line}행
          </span>
          <code className="taint-code">{n.code}</code>
        </li>
      ))}
    </ol>
  );
}

/** 관리자용 행 안 판정 편집기 — 저장하면 PATCH 응답으로 그 행만 교체한다. */
function StatusEditor({ finding, onSaved }) {
  const [value, setValue] = useState(finding.status || 'OPEN');
  const [note, setNote] = useState(finding.status_note || '');
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState('');

  const dirty = value !== (finding.status || 'OPEN') || note !== (finding.status_note || '');

  const save = async () => {
    setSaving(true);
    setError('');
    try {
      const updated = await api(`/api/findings/${finding.id}/status/`, {
        method: 'PATCH',
        body: { status: value, note },
      });
      onSaved(updated);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : '판정을 저장하지 못했습니다.');
    } finally {
      setSaving(false);
    }
  };

  return (
    <div className="status-editor">
      <select value={value} onChange={(e) => setValue(e.target.value)} disabled={saving}>
        {FINDING_STATUSES.map((s) => (
          <option key={s} value={s}>{FINDING_STATUS_LABELS[s]}</option>
        ))}
      </select>
      <input
        placeholder="사유 (선택, 200자)"
        maxLength={200}
        value={note}
        onChange={(e) => setNote(e.target.value)}
        disabled={saving}
      />
      <button type="button" className="btn" disabled={!dirty || saving} onClick={save}>
        {saving ? '저장 중…' : '저장'}
      </button>
      {error && <span className="form-error small">{error}</span>}
    </div>
  );
}

export default function RunDetailPage() {
  const { id } = useParams();
  const { isAdmin } = useAuth();
  const [run, setRun] = useState(null);
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState(null); // {count, results}
  const [severity, setSeverity] = useState(''); // '' = 전체
  const [findingStatus, setFindingStatus] = useState(''); // '' = 전체 (판정 필터)
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');
  const [executing, setExecuting] = useState(false);
  // 실행이 끝나 결과가 생기면 필터가 그대로여도 목록을 다시 읽어야 한다 — 이 값을 올려 아래
  // findings 효과를 다시 돌린다.
  const [resultsVersion, setResultsVersion] = useState(0);

  const loadRunAndSummary = useCallback(async () => {
    const [runData, summaryData] = await Promise.all([
      api(`/api/analysis-runs/${id}/`),
      api(`/api/analysis-runs/${id}/findings/summary/`),
    ]);
    setRun(runData);
    setSummary(summaryData);
  }, [id]);

  useEffect(() => {
    setError('');
    loadRunAndSummary().catch((err) => {
      setError(
        err instanceof ApiError && err.status === 404
          ? '분석 실행을 찾을 수 없습니다.'
          : '분석 실행을 불러오지 못했습니다.'
      );
    });
  }, [loadRunAndSummary]);

  useEffect(() => {
    const params = new URLSearchParams();
    if (severity) params.set('severity', severity);
    if (findingStatus) params.set('status', findingStatus);
    params.set('page', String(page));
    api(`/api/analysis-runs/${id}/findings/?${params}`)
      .then(setFindings)
      .catch(() => setFindings({ count: 0, results: [] }));
  }, [id, severity, findingStatus, page, resultsVersion]);

  // 대기열·실행중이면 상태를 주기적으로 다시 읽는다 — 실행은 워커가 하므로 완료를 알 길이
  // 폴링뿐이다. 종료 상태로 바뀌면 요약·결과 목록을 새로 읽고 필터를 처음으로 되돌린다.
  const inProgress = run ? isInProgress(run.status) : false;
  useEffect(() => {
    if (!inProgress) return undefined;
    const timer = setInterval(() => {
      api(`/api/analysis-runs/${id}/`)
        .then((next) => {
          setRun(next);
          if (!isInProgress(next.status)) {
            loadRunAndSummary().catch(() => {});
            setPage(1);
            setSeverity('');
            setFindingStatus('');
            setResultsVersion((v) => v + 1);
          }
        })
        .catch(() => {}); // 일시적 실패는 다음 폴링이 만회한다
    }, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [id, inProgress, loadRunAndSummary]);

  const changeSeverity = (value) => {
    setSeverity(value);
    setPage(1); // 필터가 바뀌면 페이지 범위도 바뀐다 — 1페이지부터.
  };

  const changeFindingStatus = (value) => {
    setFindingStatus(value);
    setPage(1);
  };

  // 판정 저장 후: 목록의 그 행만 교체하고 상단 판정 건수만 다시 읽는다 (전체 재조회 없음).
  const replaceFinding = (updated) => {
    setFindings((current) =>
      current
        ? { ...current, results: current.results.map((f) => (f.id === updated.id ? updated : f)) }
        : current
    );
    api(`/api/analysis-runs/${id}/findings/summary/`).then(setSummary).catch(() => {});
  };

  const handleExecute = async () => {
    setError('');
    setExecuting(true);
    try {
      // 응답은 큐에 등록된 상태(QUEUED). 완료 뒤 결과 갱신은 위 폴링이 한다.
      const queued = await api(`/api/analysis-runs/${id}/execute/`, { method: 'POST' });
      setRun(queued);
    } catch (err) {
      setError(err instanceof ApiError ? err.detail : '실행 요청에 실패했습니다.');
    } finally {
      setExecuting(false);
    }
  };

  if (error && !run) return <p className="form-error">{error}</p>;
  if (!run) return <p className="muted">불러오는 중…</p>;

  const totalPages = findings ? Math.max(1, Math.ceil(findings.count / PAGE_SIZE)) : 1;
  const totalAll = summary?.total ?? 0;

  return (
    <>
      <p className="breadcrumb">
        <Link to="/projects">프로젝트</Link> /{' '}
        <Link to={`/projects/${run.project}`}>{run.project_name || `#${run.project}`}</Link> / 분석 실행 {run.sequence ?? run.id}
      </p>
      <h1>
        {/* 표시는 프로젝트 내 회차 — URL·API 식별자는 여전히 전역 id */}
        분석 실행 #{run.sequence ?? run.id} <StatusBadge status={run.status} />
      </h1>
      <p className="muted">
        {run.original_filename}
        {run.created_by && <> · 실행자 {formatUser(run.created_by)}</>}
        {' '}· 업로드 {formatDateTime(run.created_at)}
        {run.status === 'QUEUED' && run.queued_at && <> · 대기열 등록 {formatDateTime(run.queued_at)}</>}
        {run.finished_at && <> · 완료 {formatDateTime(run.finished_at)}</>}
        {run.status === 'SUCCEEDED' && (
          <>
            {' '}· <Link to={`/projects/${run.project}/compare?target=${run.id}`}>이전 분석과 비교</Link>
          </>
        )}
      </p>

      {error && <p className="form-error">{error}</p>}
      {/* 폴링이 3초마다 다시 그리므로 "대기열에 오래 머묾" 판정도 자연히 갱신된다. */}
      {isQueuedTooLong(run) && <p className="form-error">{QUEUED_STALE_HINT}</p>}

      {isAdmin && (run.status === 'PENDING' || run.status === 'FAILED') && (
        <p>
          <button type="button" className="btn btn-primary" disabled={executing} onClick={handleExecute}>
            {executing ? '등록 중…' : '분석 실행'}
          </button>
        </p>
      )}
      {run.status === 'FAILED' && run.error_message && (
        <p className="form-error">실패 사유: {run.error_message}</p>
      )}

      {summary && (
        <div className="stat-row">
          <div className="stat">
            <span className="stat-number">{totalAll}</span>
            <span className="stat-label">전체 결과</span>
          </div>
          {summary.by_severity.map((s) => (
            <div className="stat" key={s.severity}>
              <span className="stat-number">{s.total}</span>
              <span className="stat-label">
                <SeverityBadge severity={s.severity} label={s.label} />
              </span>
            </div>
          ))}
        </div>
      )}

      <div className="filter-row">
        <span className="muted">심각도:</span>
        <button
          type="button"
          className={`chip ${severity === '' ? 'chip-active' : ''}`}
          onClick={() => changeSeverity('')}
        >
          전체 ({totalAll})
        </button>
        {summary?.by_severity.map((s) => (
          <button
            key={s.severity}
            type="button"
            className={`chip ${severity === s.severity ? 'chip-active' : ''}`}
            onClick={() => changeSeverity(s.severity)}
          >
            {s.label} ({s.total})
          </button>
        ))}
      </div>

      {/* 판정 필터 — 오탐으로 표시한 건을 걷어내고 보거나, 오탐만 모아 검토한다. */}
      <div className="filter-row">
        <span className="muted">판정:</span>
        <button
          type="button"
          className={`chip ${findingStatus === '' ? 'chip-active' : ''}`}
          onClick={() => changeFindingStatus('')}
        >
          전체 ({totalAll})
        </button>
        {summary?.by_status?.map((s) => (
          <button
            key={s.status}
            type="button"
            className={`chip ${findingStatus === s.status ? 'chip-active' : ''}`}
            onClick={() => changeFindingStatus(s.status)}
          >
            {s.label} ({s.total})
          </button>
        ))}
      </div>

      {findings === null && <p className="muted">결과 불러오는 중…</p>}
      {findings?.count === 0 && (
        <p className="muted">
          {run.status === 'SUCCEEDED'
            ? '조건에 맞는 결과가 없습니다.'
            : '아직 결과가 없습니다. 분석을 실행하세요.'}
        </p>
      )}

      {findings?.results.length > 0 && (
        <table className="table findings">
          <thead>
            <tr>
              <th>심각도</th>
              <th>판정</th>
              <th>진단 항목</th>
              <th>위치</th>
              <th>내용</th>
            </tr>
          </thead>
          <tbody>
            {findings.results.map((f) => (
              <tr key={f.id}>
                <td>
                  <SeverityBadge severity={f.severity} label={f.severity_label} />
                </td>
                <td>
                  <FindingStatusBadge
                    status={f.status}
                    label={f.status_label}
                    title={
                      f.status_changed_by
                        ? `${f.status_changed_by} · ${formatDateTime(f.status_changed_at)}`
                        : undefined
                    }
                  />
                  {f.status_note && (
                    <span className="muted small status-note">{f.status_note}</span>
                  )}
                  {isAdmin && (
                    <StatusEditor key={`${f.id}-${f.status}-${f.status_note}`} finding={f} onSaved={replaceFinding} />
                  )}
                </td>
                <td>
                  {f.rule_code ? (
                    <Link to={`/catalog?q=${f.rule_code}`} className="rule-code">
                      {f.rule_code}
                    </Link>
                  ) : (
                    <span className="muted">미매핑</span>
                  )}
                  {/* 어느 엔진이 잡았나 — taint(흐름 추적) 결과만 표시한다. 패턴은 기본값이라 생략. */}
                  {f.extra?.engine && f.extra.engine !== 'semgrep-pattern' && (
                    <span className="badge badge-engine" title={(f.extra.engines || [f.extra.engine]).join(' + ')}>
                      taint
                    </span>
                  )}
                  <div className="muted small">{f.rule_name}</div>
                </td>
                <td className="mono small truncate" title={`${f.file_path}:${f.start_line}`}>
                  {f.file_path}:{f.start_line}
                </td>
                <td>
                  <div>{f.message}</div>
                  {f.code_snippet && (
                    <details>
                      <summary className="muted small">코드 보기</summary>
                      <CodeSnippet finding={f} />
                      {f.extra?.taint_trace && <TaintTrace trace={f.extra.taint_trace} />}
                    </details>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {findings && findings.count > PAGE_SIZE && (
        <div className="pager">
          <button type="button" className="btn" disabled={page <= 1} onClick={() => setPage(page - 1)}>
            이전
          </button>
          <span className="muted">
            {page} / {totalPages} 페이지 (총 {findings.count}건)
          </span>
          <button
            type="button"
            className="btn"
            disabled={page >= totalPages}
            onClick={() => setPage(page + 1)}
          >
            다음
          </button>
        </div>
      )}
    </>
  );
}
