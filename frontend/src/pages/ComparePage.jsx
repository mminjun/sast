import { useEffect, useMemo, useState } from 'react';
import { Link, useParams, useSearchParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import DiffStatusBadge from '../components/DiffStatusBadge.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import { formatDateTime } from '../utils/format.js';

// 화면 필터는 전부 프론트에서 거른다 — diff 응답은 페이지네이션이 없어
// 전체 항목을 이미 들고 있다 (서버는 상태·요약만 계산).
const STATUS_LABELS = { new: '신규', resolved: '해결', persisted: '유지' };

export default function ComparePage() {
  const { projectId } = useParams();
  const [searchParams] = useSearchParams();
  const target = searchParams.get('target');
  const base = searchParams.get('base');

  const [project, setProject] = useState(null);
  const [diff, setDiff] = useState(null);
  // 분류·심각도 드롭다운의 한글 라벨은 카탈로그 집계에서 가져온다 (CatalogPage와 동일).
  const [catalogSummary, setCatalogSummary] = useState(null);
  const [error, setError] = useState('');

  const [statusFilter, setStatusFilter] = useState(''); // '' = 전체
  const [severity, setSeverity] = useState('');
  const [category, setCategory] = useState('');
  const [q, setQ] = useState('');
  // "공통 항목 없음" 힌트 닫힘 여부 — 비교 대상이 바뀌면 다시 보여준다.
  const [hintDismissed, setHintDismissed] = useState(false);

  useEffect(() => {
    api(`/api/projects/${projectId}/`)
      .then(setProject)
      .catch(() => {}); // 프로젝트명은 표시용 — 실패해도 비교 자체는 보여준다.
    api('/api/catalog/summary/')
      .then(setCatalogSummary)
      .catch(() => {});
  }, [projectId]);

  useEffect(() => {
    if (!target) return;
    setError('');
    setDiff(null);
    setHintDismissed(false);
    const qs = base ? `?base=${encodeURIComponent(base)}` : '';
    api(`/api/analysis-runs/${target}/diff/${qs}`)
      .then(setDiff)
      .catch((err) => {
        // 미할당·미존재 실행은 서버가 동일한 404를 준다 (SEC-006) — 구분하지 않는다.
        if (err instanceof ApiError && err.status === 404) {
          setError('분석 실행을 찾을 수 없습니다.');
        } else {
          setError(err instanceof ApiError ? err.detail : '비교 결과를 불러오지 못했습니다.');
        }
      });
  }, [target, base]);

  const items = useMemo(() => {
    if (!diff) return [];
    const keyword = q.trim().toLowerCase();
    return diff.items.filter(
      (item) =>
        (!statusFilter || item.status === statusFilter) &&
        (!severity || item.severity === severity) &&
        (!category || item.category === category) &&
        (!keyword ||
          [item.rule_code, item.rule_name, item.file_path].some((value) =>
            (value || '').toLowerCase().includes(keyword)
          ))
    );
  }, [diff, statusFilter, severity, category, q]);

  if (!target) {
    return (
      <p className="form-error">
        비교할 실행이 지정되지 않았습니다. <Link to={`/projects/${projectId}`}>프로젝트로 돌아가기</Link>
      </p>
    );
  }
  if (error) {
    return (
      <>
        <p className="breadcrumb">
          <Link to="/projects">프로젝트</Link> /{' '}
          <Link to={`/projects/${projectId}`}>{project?.name || `#${projectId}`}</Link> / 실행 비교
        </p>
        <p className="form-error">{error}</p>
      </>
    );
  }
  if (!diff) return <p className="muted">불러오는 중…</p>;

  const excludedTotal = (diff.excluded?.base || 0) + (diff.excluded?.target || 0);

  return (
    <>
      <p className="breadcrumb">
        <Link to="/projects">프로젝트</Link> /{' '}
        <Link to={`/projects/${projectId}`}>{project?.name || `#${projectId}`}</Link> / 실행 비교
      </p>
      <h1>
        실행 비교 {diff.base ? `#${diff.base.sequence}` : '—'} → #{diff.target.sequence}
      </h1>
      <p className="muted">
        {project?.name}
        {diff.base && (
          <>
            {' '}· 기준 <Link to={`/runs/${diff.base.id}`}>#{diff.base.sequence}</Link> (
            {formatDateTime(diff.base.created_at)})
          </>
        )}
        {' '}· 대상 <Link to={`/runs/${diff.target.id}`}>#{diff.target.sequence}</Link> (
        {formatDateTime(diff.target.created_at)})
      </p>

      {diff.note && <p className="muted">{diff.note}</p>}
      {diff.base && diff.base_auto_selected && (
        <p className="muted small">기준 실행 미지정 — 직전 완료 실행 #{diff.base.sequence}과 자동 비교합니다.</p>
      )}
      {excludedTotal > 0 && (
        <p className="muted small">
          일부 항목({excludedTotal}건)이 비교에서 제외되었습니다 (비교 키가 없는 이전 데이터).
        </p>
      )}
      {/* 두 실행이 전혀 겹치지 않으면 서로 다른 소스를 올렸을 가능성이 크다 — 경고가
          아니라 힌트: 정상적인 전면 리팩터링일 수도 있으니 판단은 사용자에게 맡긴다. */}
      {diff.base &&
        diff.summary.persisted === 0 &&
        diff.summary.new > 0 &&
        diff.summary.resolved > 0 &&
        !hintDismissed && (
          <p className="hint small">
            <span>
              이전 회차와 공통된 항목이 없습니다. 다른 소스를 올리신 게 아닌지 확인해
              주세요.
            </span>
            <button type="button" className="btn-link" onClick={() => setHintDismissed(true)}>
              닫기
            </button>
          </p>
        )}

      <div className="filter-row">
        {['new', 'resolved', 'persisted'].map((value) => (
          <button
            key={value}
            type="button"
            className={`chip ${statusFilter === value ? 'chip-active' : ''}`}
            onClick={() => setStatusFilter(statusFilter === value ? '' : value)}
          >
            {STATUS_LABELS[value]} {diff.summary[value]}
          </button>
        ))}
      </div>

      <div className="filter-row">
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">심각도: 전체</option>
          {catalogSummary?.by_severity.map((s) => (
            <option key={s.severity} value={s.severity}>
              {s.label}
            </option>
          ))}
        </select>
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">분류: 전체</option>
          {catalogSummary?.by_category.map((c) => (
            <option key={c.category} value={c.category}>
              {c.label}
            </option>
          ))}
        </select>
        <input
          placeholder="룰·파일 검색"
          value={q}
          onChange={(e) => setQ(e.target.value)}
        />
      </div>

      {diff.items.length === 0 && (
        <p className="muted">비교할 결과가 없습니다 (양쪽 실행 모두 탐지 0건).</p>
      )}
      {diff.items.length > 0 && items.length === 0 && (
        <p className="muted">조건에 맞는 항목이 없습니다.</p>
      )}

      {items.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>상태</th>
              <th>룰</th>
              <th>파일 경로</th>
              <th>심각도</th>
              <th>라인</th>
            </tr>
          </thead>
          <tbody>
            {items.map((item, index) => (
              <tr key={`${item.status}-${index}`}>
                <td>
                  <DiffStatusBadge status={item.status} />
                </td>
                <td>
                  {item.rule_code ? (
                    <Link to={`/catalog?q=${item.rule_code}`} className="rule-code">
                      {item.rule_code}
                    </Link>
                  ) : (
                    <span className="muted">미매핑</span>
                  )}
                  <div className="muted small">{item.rule_name}</div>
                </td>
                <td className="mono small truncate" title={item.file_path}>
                  {item.file_path}
                </td>
                <td>
                  <SeverityBadge severity={item.severity} />
                </td>
                <td className="mono small">{item.start_line}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
