import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from './AuthContext.jsx';

/** 보호 라우트 — 미인증이면 /login으로, 로그인 후 원래 위치로 돌아온다. */
export default function RequireAuth({ children }) {
  const { user, booting } = useAuth();
  const location = useLocation();

  if (booting) return <div className="page-loading">세션 확인 중…</div>;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  return children;
}
