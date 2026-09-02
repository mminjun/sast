// 서버가 severity_label을 주는 응답은 그 값을 쓰고, 없는 응답(diff 항목 등)은
// 여기 한글 폴백을 쓴다 — 화면마다 영문/한글이 갈리지 않게 한 곳에서 정한다.
const FALLBACK_LABELS = {
  HIGH: '높음',
  MEDIUM: '보통',
  LOW: '낮음',
};

/** 심각도 배지 — 결과 화면·카탈로그·비교 공용. */
export default function SeverityBadge({ severity, label }) {
  return (
    <span className={`badge severity-${(severity || 'unknown').toLowerCase()}`}>
      {label || FALLBACK_LABELS[severity] || severity || '—'}
    </span>
  );
}
