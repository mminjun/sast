import { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { formatUser } from '../utils/format.js';

const PAGE_SIZE = 50; // 서버 FindingPagination.page_size와 동일

export default function RunDetailPage() {
  const { id } = useParams();
  const { isAdmin } = useAuth();
  const [run, setRun] = useState(null);
  const [summary, setSummary] = useState(null);
  const [findings, setFindings] = useState(null); // {count, results}
  const [severity, setSeverity] = useState(''); // '' = 전체
  const [page, setPage] = useState(1);
  const [error, setError] = useState('');
  const [executing, setExecuting] = useState(false);

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
    params.set('page', String(page));
    api(`/api/analysis-runs/${id}/findings/?${params}`)
      .then(setFindings)
      .catch(() => setFindings({ count: 0, results: [] }));
  }, [id, severity, page]);

  const changeSeverity = (value) => {
    setSeverity(value);
    setPage(1); // 필터가 바뀌면 페이지 범위도 바뀐다 — 1페이지부터.
  };

  const handleExecute = async () => {
    setError('');
    setExecuting(true);
    try {
      await api(`/api/analysis-runs/${id}/execute/`, { method: 'POST' });
      await loadRunAndSummary();
      setPage(1);
      setSeverity('');
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
        <Link to={`/projects/${run.project}`}>#{run.project}</Link> / 분석 실행 {run.id}
      </p>
      <h1>
        분석 실행 #{run.id} <StatusBadge status={run.status} />
      </h1>
      <p className="muted">
        {run.original_filename}
        {run.created_by && <> · 실행자 {formatUser(run.created_by)}</>}
        {' '}· 업로드 {new Date(run.created_at).toLocaleString('ko-KR')}
        {run.finished_at && <> · 완료 {new Date(run.finished_at).toLocaleString('ko-KR')}</>}
      </p>

      {error && <p className="form-error">{error}</p>}

      {isAdmin && (run.status === 'PENDING' || run.status === 'FAILED') && (
        <p>
          <button type="button" className="btn btn-primary" disabled={executing} onClick={handleExecute}>
            {executing ? '분석 중… (최대 2분)' : '분석 실행'}
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
                  {f.rule_code ? (
                    <Link to={`/catalog?q=${f.rule_code}`} className="rule-code">
                      {f.rule_code}
                    </Link>
                  ) : (
                    <span className="muted">미매핑</span>
                  )}
                  <div className="muted small">{f.rule_name}</div>
                </td>
                <td className="mono small">
                  {f.file_path}:{f.start_line}
                </td>
                <td>
                  <div>{f.message}</div>
                  {f.code_snippet && (
                    <details>
                      <summary className="muted small">코드 보기</summary>
                      <pre className="snippet">{f.code_snippet}</pre>
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
