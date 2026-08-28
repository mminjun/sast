import { Navigate, useLocation } from 'react-router-dom';

import { useAuth } from './AuthContext.jsx';

/**
 * 관리자 전용 라우트 — 일반 사용자는 /projects로 돌려보낸다.
 * 이 가드는 UI 편의일 뿐이다. 실제 차단은 서버의 IsAdminRole이 담당한다 (SEC-003).
 */
export default function RequireAdmin({ children }) {
  const { user, booting, isAdmin } = useAuth();
  const location = useLocation();

  if (booting) return <div className="page-loading">세션 확인 중…</div>;
  if (!user) return <Navigate to="/login" replace state={{ from: location }} />;
  if (!isAdmin) return <Navigate to="/projects" replace />;
  return children;
}
