// diff 3상태. 상태 문자열은 catalog/services.py diff_findings와 일치해야 한다.
const LABELS = {
  new: '신규',
  resolved: '해결',
  persisted: '유지',
};

export default function DiffStatusBadge({ status }) {
  return (
    <span className={`badge diff-${status || 'unknown'}`}>
      {LABELS[status] || status || '—'}
    </span>
  );
}
