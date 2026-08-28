// 인증 상태 — 화면 간 공유가 필요한 유일한 전역 상태라 Context 하나로 충분하다.
import { createContext, useContext, useEffect, useState } from 'react';

import {
  api,
  clearSession,
  getRefreshToken,
  hasRefreshToken,
  setOnSessionExpired,
  setSession,
} from '../api/client.js';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  // 부팅 중(세션 복원 시도 전)에 로그인 화면으로 튕기지 않도록 구분한다.
  const [booting, setBooting] = useState(true);

  useEffect(() => {
    setOnSessionExpired(() => setUser(null));

    (async () => {
      // access는 메모리에만 있어 새로고침 후엔 없다 — refresh가 남아 있으면
      // /me 호출이 401→갱신→재시도 경로로 세션을 복원한다.
      if (hasRefreshToken()) {
        try {
          setUser(await api('/api/auth/me/'));
        } catch {
          // 갱신까지 실패 — 로그인 화면으로 보낸다(client.js가 세션을 정리했다).
        }
      }
      setBooting(false);
    })();
  }, []);

  const login = async (email, password) => {
    const tokens = await api('/api/auth/login/', {
      method: 'POST',
      body: { email, password },
      noAuthRetry: true,
    });
    setSession(tokens);
    setUser(await api('/api/auth/me/'));
  };

  const logout = async () => {
    const refresh = getRefreshToken();
    try {
      // 서버 blacklist 처리 — 실패해도 로컬 세션은 지운다(오프라인이어도 로그아웃 가능).
      // noAuthRetry: access가 만료된 상태에서 갱신을 거치면 본문의 refresh가 rotation으로
      // 이미 폐기된 값이 되어 blacklist가 조용히 실패하고, 새로 발급된 refresh만 서버에
      // 유효하게 남는다 — 그 경우 로컬 정리만 하는 편이 낫다 (secure-review).
      await api('/api/auth/logout/', { method: 'POST', body: { refresh }, noAuthRetry: true });
    } catch {
      // 무시 — 아래에서 로컬 정리
    }
    clearSession();
    setUser(null);
  };

  const value = {
    user,
    booting,
    isAdmin: user?.role === 'ADMIN',
    login,
    logout,
  };
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  return useContext(AuthContext);
}
