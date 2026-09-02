import { useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';

import { api } from '../api/client.js';
import DiffStatusBadge from './DiffStatusBadge.jsx';

// 심각도 색은 SeverityBadge와 같은 팔레트(index.css 변수)를 쓴다.
const SEGMENTS = [
  { key: 'high', label: 'HIGH', className: 'trend-seg-high' },
  { key: 'medium', label: 'MEDIUM', className: 'trend-seg-medium' },
  { key: 'low', label: 'LOW', className: 'trend-seg-low' },
];
const BAR_AREA_HEIGHT = 120; // px — 추이 막대 영역의 최대 높이
const COMPARE_PREVIEW_COUNT = 5;
const TOP_RULE_COUNT = 5;

function total(counts) {
  return (counts?.high || 0) + (counts?.medium || 0) + (counts?.low || 0);
}

/** 프로젝트 상세 상단 대시보드 — 최신 완료 실행과 직전 diff 기준 (RFP 외 자체 개선). */
export default function ProjectDashboard({ projectId, runs }) {
  // runs는 부모가 내려준 전체 실행 목록(최신순) — 여기서 프론트로 자른다.
  const succeeded = useMemo(() => runs.filter((r) => r.status === 'SUCCEEDED'), [runs]);
  const latest = succeeded[0];
  const latestId = latest?.id;

  const [diff, setDiff] = useState(null);
  const [diffFailed, setDiffFailed] = useState(false);
  const [summary, setSummary] = useState(null);
  const [windowSize, setWindowSize] = useState('10'); // '10' | '20' | 'all'

  useEffect(() => {
    if (!latestId) return;
    setDiff(null);
    setDiffFailed(false);
    setSummary(null);
    api(`/api/analysis-runs/${latestId}/diff/`)
      .then(setDiff)
      .catch(() => setDiffFailed(true)); // 대시보드는 부가 정보 — 실패해도 페이지는 유지.
    api(`/api/analysis-runs/${latestId}/findings/summary/`)
      .then(setSummary)
      .catch(() => {});
  }, [latestId]);

  // 실패한 실행만 있는 프로젝트 — 깨진 화면 대신 안내 (시연 경로).
  if (!latest) {
    return <p className="muted">완료된 분석 실행이 없어 대시보드를 표시할 수 없습니다.</p>;
  }

  const counts = latest.severity_counts || { high: 0, medium: 0, low: 0 };
  // 비교 대상이 없으면(완료 실행 1개뿐) 신규·해결은 수치 대신 "—" (빈 상태 처리).
  const hasBase = Boolean(diff?.base);

  const trendRuns = (windowSize === 'all' ? succeeded : succeeded.slice(0, Number(windowSize)))
    .slice()
    .reverse(); // 화면은 오래된 실행 → 최신 순
  const trendMax = Math.max(1, ...trendRuns.map((r) => total(r.severity_counts)));

  const compareItems = diff ? diff.items.slice(0, COMPARE_PREVIEW_COUNT) : [];
  const topRules = summary
    ? [...summary.by_rule].sort((a, b) => b.total - a.total).slice(0, TOP_RULE_COUNT)
    : [];
  const topRuleMax = Math.max(1, ...topRules.map((r) => r.total));

  return (
    <>
      <div className="stat-row">
        <div className="stat">
          <span className="stat-number">{total(counts)}</span>
          <span className="stat-label muted">최근 실행 탐지 (#{latest.sequence ?? latest.id})</span>
        </div>
        <div className="stat">
          <span className={`stat-number ${hasBase && diff.summary.new > 0 ? 'stat-up' : ''}`}>
            {hasBase ? `+${diff.summary.new}` : '—'}
          </span>
          <span className="stat-label muted">신규</span>
        </div>
        <div className="stat">
          <span className={`stat-number ${hasBase && diff.summary.resolved > 0 ? 'stat-down' : ''}`}>
            {hasBase ? `−${diff.summary.resolved}` : '—'}
          </span>
          <span className="stat-label muted">해결</span>
        </div>
        <div className="stat">
          <span className="stat-number">{counts.high}</span>
          <span className="stat-label muted">HIGH 잔존</span>
        </div>
      </div>
      {!hasBase && !diffFailed && diff && (
        <p className="muted small">이전 완료 실행이 없어 신규·해결을 계산할 수 없습니다.</p>
      )}
      {diffFailed && <p className="muted small">비교 정보를 불러오지 못했습니다.</p>}

      <div className="card">
        <div className="trend-header">
          <span className="trend-title">
            <strong>실행별 탐지 추이</strong>
            <span className="trend-legend small">
              <span className="trend-legend-high">HIGH</span> /{' '}
              <span className="trend-legend-medium">MEDIUM</span> /{' '}
              <span className="trend-legend-low">LOW</span>
            </span>
          </span>
          <select value={windowSize} onChange={(e) => setWindowSize(e.target.value)}>
            <option value="10">최근 10회</option>
            <option value="20">최근 20회</option>
            <option value="all">전체</option>
          </select>
        </div>
        <div className="trend-bars">
          {trendRuns.map((run) => {
            const runCounts = run.severity_counts || { high: 0, medium: 0, low: 0 };
            return (
              <Link
                key={run.id}
                to={`/runs/${run.id}`}
                className="trend-bar"
                title={`#${run.sequence ?? run.id} — 높음 ${runCounts.high} · 보통 ${runCounts.medium} · 낮음 ${runCounts.low}`}
              >
                <span className="trend-stack">
                  {total(runCounts) === 0 && <span className="trend-zero small">0</span>}
                  {SEGMENTS.map(({ key, className }) => {
                    const value = runCounts[key] || 0;
                    if (!value) return null;
                    return (
                      <span
                        key={key}
                        className={`trend-seg ${className}`}
                        style={{ height: `${Math.max(3, (value / trendMax) * BAR_AREA_HEIGHT)}px` }}
                      />
                    );
                  })}
                </span>
                <span className="trend-label">#{run.sequence ?? run.id}</span>
              </Link>
            );
          })}
        </div>
      </div>

      <div className="dashboard-grid">
        <div className="card">
          <div className="trend-header">
            <strong>
              실행 비교 {hasBase ? `#${diff.base.sequence} → #${diff.target.sequence}` : ''}
            </strong>
            <Link to={`/projects/${projectId}/compare?target=${latest.id}`}>전체 보기</Link>
          </div>
          {!diff && !diffFailed && <p className="muted">불러오는 중…</p>}
          {diff?.note && <p className="muted small">{diff.note}</p>}
          {diff && compareItems.length === 0 && !diff.note && (
            <p className="muted">비교할 변화가 없습니다.</p>
          )}
          {compareItems.length > 0 && (
            <ul className="widget-list">
              {compareItems.map((item, index) => (
                <li key={index} className="widget-row">
                  <DiffStatusBadge status={item.status} />
                  <span
                    className="widget-main truncate"
                    title={`${item.rule_name || item.rule_code || '미매핑'} — ${item.file_path}:${item.start_line}`}
                  >
                    {item.rule_name || item.rule_code || '미매핑'}{' '}
                    <span className="mono small muted">
                      — {item.file_path}:{item.start_line}
                    </span>
                  </span>
                  <span className={`small trend-legend-${item.severity.toLowerCase()}`}>
                    {item.severity}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="trend-header">
            <strong>룰별 탐지 상위</strong>
          </div>
          {summary && topRules.length === 0 && (
            <p className="muted">탐지된 결과가 없습니다.</p>
          )}
          {topRules.length > 0 && (
            <ul className="widget-list">
              {topRules.map((rule) => (
                <li key={`${rule.rule_code}-${rule.rule_name}`} className="widget-row widget-row-stack">
                  <span className="widget-main">
                    {rule.rule_name || rule.rule_code || '미매핑'}
                    <span className="widget-count">{rule.total}</span>
                  </span>
                  <span className="rule-bar-track">
                    <span
                      className={`rule-bar rule-bar-${rule.severity.toLowerCase()}`}
                      style={{ width: `${(rule.total / topRuleMax) * 100}%` }}
                    />
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </>
  );
}
