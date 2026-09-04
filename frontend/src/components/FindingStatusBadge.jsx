// 진단 결과의 판정 3상태 (오탐 관리). 값·표기는 catalog/models.py FindingStatus와 일치해야 한다.
export const FINDING_STATUS_LABELS = {
  OPEN: '미처리',
  FALSE_POSITIVE: '오탐',
  ACCEPTED: '수용',
};

export default function FindingStatusBadge({ status, label, title }) {
  const value = status || 'OPEN';
  return (
    <span className={`badge fstatus-${value.toLowerCase()}`} title={title}>
      {label || FINDING_STATUS_LABELS[value] || value}
    </span>
  );
}
