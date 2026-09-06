// 분석 실행 5상태 (SFR-015). 상태 문자열은 analysis/models.py AnalysisStatus와 일치해야 한다.
// QUEUED(대기열)는 실행을 요청했고 워커가 집어 가길 기다리는 상태 — PENDING(업로드만 됨)과
// 구분해야 "아직 안 눌렀음"과 "눌렀는데 기다리는 중"을 사용자가 알 수 있다.
const LABELS = {
  PENDING: '대기',
  QUEUED: '대기열',
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
