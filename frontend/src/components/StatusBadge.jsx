// 분석 실행 4상태 (SFR-015). 상태 문자열은 analysis/models.py AnalysisStatus와 일치해야 한다.
const LABELS = {
  PENDING: '대기',
  RUNNING: '실행중',
  SUCCEEDED: '완료',
  FAILED: '실패',
};

export default function StatusBadge({ status }) {
  return (
    <span className={`badge status-${(status || 'unknown').toLowerCase()}`}>
      {LABELS[status] || status || '—'}
    </span>
  );
}
