/** 심각도 배지 — 결과 화면·카탈로그 공용. label은 서버가 내려준 한글 표기를 쓴다. */
export default function SeverityBadge({ severity, label }) {
  return (
    <span className={`badge severity-${(severity || 'unknown').toLowerCase()}`}>
      {label || severity || '—'}
    </span>
  );
}
