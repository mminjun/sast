import { NavLink, Outlet, useNavigate } from 'react-router-dom';

import { useAuth } from '../auth/AuthContext.jsx';

/** 공통 레이아웃 — 상단 네비 + 사용자 정보 + 로그아웃. */
export default function Layout() {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login', { replace: true });
  };

  return (
    <div className="app">
      <header className="topbar">
        <span className="brand">SAST</span>
        <nav>
          <NavLink to="/projects">프로젝트</NavLink>
          <NavLink to="/catalog">진단 기준</NavLink>
          {isAdmin && <NavLink to="/users">사용자 관리</NavLink>}
        </nav>
        <div className="topbar-user">
          <span className="user-email">{user?.email}</span>
          <span className={`badge role-${isAdmin ? 'admin' : 'user'}`}>
            {isAdmin ? '관리자' : '일반'}
          </span>
          <button type="button" className="btn btn-ghost" onClick={handleLogout}>
            로그아웃
          </button>
        </div>
      </header>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
