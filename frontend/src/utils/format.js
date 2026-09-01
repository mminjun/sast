/** 사용자 표시 공통 형식 — 이름이 있으면 "email (이름)", 없으면 email만. */
export function formatUser(user) {
  if (!user) return '—';
  return user.name ? `${user.email} (${user.name})` : user.email;
}
