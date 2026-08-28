import { useEffect, useState } from 'react';
import { useSearchParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import SeverityBadge from '../components/SeverityBadge.jsx';

export default function CatalogPage() {
  // 결과 화면에서 /catalog?q=KISA-SF-06 링크로 진입할 수 있게 q는 URL과 동기화한다.
  const [searchParams, setSearchParams] = useSearchParams();
  const [summary, setSummary] = useState(null);
  const [rules, setRules] = useState(null);
  const [error, setError] = useState('');
  const [category, setCategory] = useState('');
  const [severity, setSeverity] = useState('');
  const [implemented, setImplemented] = useState('');
  const q = searchParams.get('q') || '';

  useEffect(() => {
    api('/api/catalog/summary/')
      .then(setSummary)
      .catch(() => {});
  }, []);

  useEffect(() => {
    const params = new URLSearchParams();
    if (category) params.set('category', category);
    if (severity) params.set('severity', severity);
    if (implemented) params.set('implemented', implemented);
    if (q) params.set('q', q);
    const qs = params.toString();
    setError('');
    api(`/api/catalog/rules/${qs ? `?${qs}` : ''}`)
      .then(setRules)
      .catch((err) =>
        setError(err instanceof ApiError ? err.detail : '카탈로그를 불러오지 못했습니다.')
      );
  }, [category, severity, implemented, q]);

  return (
    <>
      <h1>KISA 진단 기준</h1>
      {summary && (
        <p className="muted">
          전체 {summary.total}개 중 <strong>{summary.implemented}개</strong> 실탐지 구현
          (미구현 {summary.not_implemented}개는 대상 언어·범위 밖 — 기준 자체는 전부 등록)
        </p>
      )}

      <div className="filter-row">
        <select value={category} onChange={(e) => setCategory(e.target.value)}>
          <option value="">유형: 전체</option>
          {summary?.by_category.map((c) => (
            <option key={c.category} value={c.category}>
              {c.label} ({c.implemented}/{c.total})
            </option>
          ))}
        </select>
        <select value={severity} onChange={(e) => setSeverity(e.target.value)}>
          <option value="">심각도: 전체</option>
          {summary?.by_severity.map((s) => (
            <option key={s.severity} value={s.severity}>
              {s.label} ({s.total})
            </option>
          ))}
        </select>
        <select value={implemented} onChange={(e) => setImplemented(e.target.value)}>
          <option value="">구현 여부: 전체</option>
          <option value="true">실탐지 구현</option>
          <option value="false">미구현</option>
        </select>
        <input
          placeholder="코드·이름·설명 검색"
          value={q}
          onChange={(e) =>
            setSearchParams(e.target.value ? { q: e.target.value } : {}, { replace: true })
          }
        />
      </div>

      {/* 등급 의미는 서버 데이터가 아니라 등급 정책(docs/decisions.md 2026-08-27)의 요약 —
          정책이 바뀌면 여기도 함께 고친다. label은 severity_label과 같은 한글 표기. */}
      <div className="card severity-legend">
        <div className="severity-legend-row">
          <SeverityBadge severity="HIGH" label="높음" />
          <span>성공 시 그 자체로 침해가 완성 (원격 코드 실행·인증 우회·자격증명 직접 노출)</span>
        </div>
        <div className="severity-legend-row">
          <SeverityBadge severity="MEDIUM" label="보통" />
          <span>단독으론 제한적, 추가 조건이나 후속 공격의 발판이 되는 간접 영향</span>
        </div>
        <div className="severity-legend-row">
          <SeverityBadge severity="LOW" label="낮음" />
          <span>직접 악용 경로가 아닌 코드 품질·방어적 개선 수준</span>
        </div>
        <p className="muted small">
          KISA 가이드는 항목을 유형으로만 분류하므로 심각도는 악용에 추가 조건이 필요한지를
          기준으로 개발자가 부여했습니다. 카탈로그에 매핑되지 않은 탐지는 Semgrep 기본 등급을
          따르고, 그마저 불명확하면 누락 방지를 위해 보통으로 둡니다.
        </p>
      </div>

      {error && <p className="form-error">{error}</p>}
      {rules === null && !error && <p className="muted">불러오는 중…</p>}
      {rules?.length === 0 && <p className="muted">조건에 맞는 진단 기준이 없습니다.</p>}

      {rules?.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>코드</th>
              <th>이름</th>
              <th>유형</th>
              <th>심각도</th>
              <th>실탐지</th>
            </tr>
          </thead>
          <tbody>
            {rules.map((rule) => (
              <tr key={rule.code}>
                <td className="mono">{rule.code}</td>
                <td>
                  <details>
                    <summary>{rule.name}</summary>
                    <div className="rule-detail">
                      <p>{rule.description}</p>
                      {rule.severity_reason && (
                        <p className="muted small">등급 근거: {rule.severity_reason}</p>
                      )}
                    </div>
                  </details>
                </td>
                <td>{rule.category_label}</td>
                <td>
                  <SeverityBadge severity={rule.severity} label={rule.severity_label} />
                </td>
                <td>{rule.is_implemented ? '✓' : <span className="muted">—</span>}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
