import { useEffect, useState } from 'react';
import { Link } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { formatDate, formatUser } from '../utils/format.js';

export default function ProjectListPage() {
  // 관리자 전용 UI 노출은 편의일 뿐이다 — 실제 차단은 서버의 IsAdminRole·스코프
  // 쿼리셋이 담당한다 (SEC-003~005). role을 위조해도 서버가 거부한다.
  const { isAdmin } = useAuth();
  const [projects, setProjects] = useState(null);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');

  useEffect(() => {
    api('/api/projects/')
      .then(setProjects)
      .catch((err) => setError(err instanceof ApiError ? err.detail : '목록을 불러오지 못했습니다.'));
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    setCreateError('');
    setCreating(true);
    try {
      const project = await api('/api/projects/', {
        method: 'POST',
        body: { name, description },
      });
      setProjects((prev) => [project, ...(prev || [])]);
      setName('');
      setDescription('');
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.detail : '생성에 실패했습니다.');
    } finally {
      setCreating(false);
    }
  };

  return (
    <>
      <h1>프로젝트</h1>

      {isAdmin && (
        <form className="card form-inline" onSubmit={handleCreate}>
          <input
            placeholder="프로젝트 이름"
            value={name}
            onChange={(e) => setName(e.target.value)}
            required
          />
          <input
            placeholder="설명 (선택)"
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          <button type="submit" className="btn btn-primary" disabled={creating}>
            {creating ? '생성 중…' : '프로젝트 생성'}
          </button>
          <span className="muted">
            분석 대상 소스 하나를 프로젝트로 등록합니다. 수정된 버전은 같은 프로젝트에
            다시 업로드해 이력을 쌓으세요.
          </span>
          {createError && <p className="form-error">{createError}</p>}
        </form>
      )}

      {error && <p className="form-error">{error}</p>}
      {projects === null && !error && <p className="muted">불러오는 중…</p>}
      {projects?.length === 0 && (
        <p className="muted">
          {isAdmin ? '프로젝트가 없습니다. 위에서 생성하세요.' : '할당된 프로젝트가 없습니다.'}
        </p>
      )}

      {projects?.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>이름</th>
              <th>설명</th>
              <th>생성자</th>
              <th>생성일</th>
            </tr>
          </thead>
          <tbody>
            {projects.map((p) => (
              <tr key={p.id}>
                <td>
                  <Link to={`/projects/${p.id}`}>{p.name}</Link>
                </td>
                <td className="muted">{p.description || '—'}</td>
                <td>{formatUser(p.created_by)}</td>
                <td>{formatDate(p.created_at)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
