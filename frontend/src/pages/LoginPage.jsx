import { useState } from 'react';
import { Navigate, useLocation, useNavigate } from 'react-router-dom';

import { ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';

export default function LoginPage() {
  const { user, login } = useAuth();
  const navigate = useNavigate();
  const location = useLocation();
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [error, setError] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // 이미 로그인된 상태로 /login에 오면 목록으로 보낸다.
  if (user) return <Navigate to="/projects" replace />;

  const from = location.state?.from?.pathname || '/projects';

  const handleSubmit = async (event) => {
    event.preventDefault();
    setError('');
    setSubmitting(true);
    try {
      await login(email, password);
      navigate(from, { replace: true });
    } catch (err) {
      if (err instanceof ApiError && err.status === 401) {
        // simplejwt의 영문 detail 대신 화면용 메시지 — 어떤 쪽이 틀렸는지는 알려주지 않는다.
        setError('이메일 또는 비밀번호가 올바르지 않습니다.');
      } else if (err instanceof ApiError && err.status === 429) {
        setError('로그인 시도가 너무 잦습니다. 잠시 후 다시 시도하세요. (5회/분 제한)');
      } else {
        setError(err instanceof ApiError ? err.detail : '서버에 연결할 수 없습니다.');
      }
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="login-wrap">
      <form className="login-card" onSubmit={handleSubmit}>
        <h1>SAST</h1>
        <p className="muted">KISA 개발보안 가이드 기반 정적 분석</p>
        <label>
          이메일
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            autoComplete="username"
            required
          />
        </label>
        <label>
          비밀번호
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
          />
        </label>
        {error && <p className="form-error">{error}</p>}
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? '로그인 중…' : '로그인'}
        </button>
      </form>
    </div>
  );
}
