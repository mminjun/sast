/** 분석 실행 상태 판정 — 폴링·대기열 힌트의 규칙을 한 곳에 둔다.
 *
 * 실행 요청은 큐에 등록만 하고(QUEUED) 별도 워커가 처리하므로, 화면은 완료를 폴링으로만
 * 알 수 있다 (docs/decisions.md 2026-09-06). 상태 문자열은 analysis/models.py AnalysisStatus.
 */

/** 워커가 아직 끝내지 않은 상태 — 이 상태가 하나라도 있으면 폴링한다. */
export const IN_PROGRESS_STATUSES = ['QUEUED', 'RUNNING'];

/** 폴링 간격(ms). 실행이 수십 초~분 단위라 3초면 충분하고 서버 부담도 적다. */
export const POLL_INTERVAL_MS = 3000;

/** 이보다 오래 대기열에 머물면 "워커가 떠 있는지 확인" 힌트를 띄운다(ms).
 *  개발 환경에서 워커를 안 띄운 채 실행을 누르면 QUEUED에 계속 머무는데, "처리 중"인지
 *  "워커가 없어 안 도는지" 화면만 봐선 구분이 안 되기 때문이다. 서버 하트비트 API 없이
 *  queued_at과의 시각 차이만으로 판단한다. */
export const QUEUED_STALE_MS = 5 * 60 * 1000;

export const QUEUED_STALE_HINT =
  '대기열에 5분 이상 머물러 있습니다. 워커(python manage.py analysis_worker)가 실행 중인지 확인하세요.';

export function isInProgress(status) {
  return IN_PROGRESS_STATUSES.includes(status);
}

export function isQueuedTooLong(run, now = Date.now()) {
  if (!run || run.status !== 'QUEUED' || !run.queued_at) return false;
  return now - new Date(run.queued_at).getTime() >= QUEUED_STALE_MS;
}
