/** 사용자 표시 공통 형식 — 이름이 있으면 "email (이름)", 없으면 email만. */
export function formatUser(user) {
  if (!user) return '—';
  return user.name ? `${user.email} (${user.name})` : user.email;
}

/** 날짜만 (예: 2026. 9. 2.) — 목록처럼 시각까지 필요 없는 곳. */
export function formatDate(value) {
  return value ? new Date(value).toLocaleDateString('ko-KR') : '—';
}

/** 날짜+시각, 분까지 (예: 2026. 9. 2. 오전 10:46) — 초는 화면에서 의미가 없다. */
export function formatDateTime(value) {
  if (!value) return '—';
  return new Date(value).toLocaleString('ko-KR', { dateStyle: 'medium', timeStyle: 'short' });
}
