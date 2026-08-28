// API 호출 공통 계층 — 토큰 첨부, 만료 시 갱신, 오류 표준화.
//
// 토큰 보관 정책 (보안 트레이드오프 — docs/decisions.md):
// - access: JS 메모리에만 둔다. 수명 30분이라 새로고침 시 소멸해도 refresh로 재발급된다.
// - refresh: sessionStorage. 같은 탭 새로고침(F5)에서 세션이 살아남고, 탭을 닫으면
//   소멸한다. localStorage는 브라우저 재시작 후에도 디스크에 남아 탈취 창이 가장 넓어
//   쓰지 않는다. XSS가 sessionStorage를 읽을 수 있다는 잔여 위험은 수용하되, 백엔드의
//   refresh rotation+blacklist가 탈취 토큰의 수명을 줄인다.
// - httpOnly 쿠키는 백엔드 수정(쿠키 발급+CSRF 방어)이 필요해 채택하지 않았다.

const REFRESH_KEY = 'sast.refresh';

let accessToken = null;
let onSessionExpired = null;

export class ApiError extends Error {
  constructor(status, data) {
    super(`API ${status}`);
    this.status = status;
    this.data = data;
  }

  /** DRF 오류 본문({detail} 또는 {필드: [메시지]})을 화면용 한 줄로 만든다. */
  get detail() {
    if (!this.data) return `요청 실패 (HTTP ${this.status})`;
    if (typeof this.data.detail === 'string') return this.data.detail;
    const messages = Object.values(this.data).flat().filter((v) => typeof v === 'string');
    return messages.length ? messages.join(' ') : `요청 실패 (HTTP ${this.status})`;
  }
}

export function setSession({ access, refresh }) {
  accessToken = access;
  if (refresh) sessionStorage.setItem(REFRESH_KEY, refresh);
}

export function clearSession() {
  accessToken = null;
  sessionStorage.removeItem(REFRESH_KEY);
}

export function hasRefreshToken() {
  return Boolean(sessionStorage.getItem(REFRESH_KEY));
}

export function getRefreshToken() {
  return sessionStorage.getItem(REFRESH_KEY);
}

/** 갱신까지 실패해 세션이 끝났을 때 호출될 콜백(AuthContext가 등록). */
export function setOnSessionExpired(fn) {
  onSessionExpired = fn;
}

// refresh는 single-flight — 동시에 401이 여러 개 떠도 갱신 호출은 한 번만 하고,
// 나머지 요청은 진행 중인 Promise를 공유해 결과를 기다렸다가 재시도한다.
// 백엔드가 ROTATE_REFRESH_TOKENS+BLACKLIST_AFTER_ROTATION이라, 갱신을 중복 호출하면
// 두 번째 호출이 이미 폐기(blacklist)된 토큰을 쓰게 되어 멀쩡한 세션이 로그아웃된다.
let refreshPromise = null;

function refreshAccess() {
  if (!refreshPromise) {
    refreshPromise = doRefresh().finally(() => {
      refreshPromise = null;
    });
  }
  return refreshPromise;
}

async function doRefresh() {
  const refresh = sessionStorage.getItem(REFRESH_KEY);
  if (!refresh) throw new ApiError(401, { detail: '로그인이 필요합니다.' });

  const res = await fetch('/api/auth/refresh/', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ refresh }),
  });
  if (!res.ok) {
    // 세션 정리는 토큰이 실제로 거부된 경우(401/403)에만 한다 — 일시 장애(500·429)에
    // 지우면 서버에선 유효한 refresh를 blacklist 없이 로컬에서만 버리게 된다 (secure-review).
    if (res.status === 401 || res.status === 403) {
      clearSession();
      if (onSessionExpired) onSessionExpired();
      throw new ApiError(res.status, { detail: '세션이 만료되었습니다. 다시 로그인하세요.' });
    }
    throw new ApiError(res.status, { detail: '세션 갱신에 실패했습니다. 잠시 후 다시 시도하세요.' });
  }
  const data = await res.json();
  // rotation이 켜져 있어 응답에 새 refresh가 함께 온다 — 이전 것은 서버가 폐기했다.
  setSession(data);
  return data.access;
}

/**
 * 공통 fetch 래퍼.
 * @param {string} path - /api/... 경로 (Vite dev proxy가 Django로 넘긴다)
 * @param {object} [options]
 * @param {string} [options.method]
 * @param {object} [options.body] - JSON 직렬화해 전송
 * @param {FormData} [options.form] - multipart 전송(zip 업로드). body와 배타
 * @param {boolean} [options.noAuthRetry] - 401이어도 갱신·재시도하지 않음(login/logout용)
 */
export async function api(path, { method = 'GET', body, form, noAuthRetry = false } = {}) {
  const doFetch = () => {
    const headers = {};
    if (accessToken) headers.Authorization = `Bearer ${accessToken}`;
    let payload;
    if (form) {
      payload = form; // Content-Type은 브라우저가 boundary와 함께 설정한다.
    } else if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      payload = JSON.stringify(body);
    }
    return fetch(path, { method, headers, body: payload });
  };

  let res = await doFetch();

  if (res.status === 401 && !noAuthRetry && hasRefreshToken()) {
    await refreshAccess(); // 실패 시 여기서 세션 정리 후 throw
    res = await doFetch();
  }

  if (!res.ok) {
    let data = null;
    try {
      data = await res.json();
    } catch {
      // 본문이 JSON이 아니면 상태 코드만으로 처리한다.
    }
    throw new ApiError(res.status, data);
  }

  if (res.status === 204) return null;
  return res.json();
}
