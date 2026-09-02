import { useEffect, useRef, useState } from 'react';

/** 할당 프로젝트 전체 목록 팝오버 — 셀은 요약만 보여주고 클릭 시 띄운다.

    테이블 카드가 라운드 코너용 overflow:hidden이라 absolute로는 경계에서
    잘린다 — position:fixed(뷰포트 기준)로 띄우고, 열려 있는 동안 스크롤·
    리사이즈마다 트리거 위치를 다시 계산한다. */
function ProjectsPopover({ projects, open, onToggle }) {
  const triggerRef = useRef(null);
  const [position, setPosition] = useState({ top: 0, left: 0 });

  useEffect(() => {
    if (!open) return undefined;
    const place = () => {
      const rect = triggerRef.current?.getBoundingClientRect();
      if (!rect) return;
      setPosition({
        top: rect.bottom + 6,
        // 뷰포트 오른쪽 밖으로 나가지 않게 여유폭(팝오버 max-width+α)만큼 당긴다.
        left: Math.max(8, Math.min(rect.left, window.innerWidth - 340)),
      });
    };
    place();
    // capture — 페이지 스크롤뿐 아니라 내부 스크롤 컨테이너에도 반응한다.
    window.addEventListener('scroll', place, true);
    window.addEventListener('resize', place);
    return () => {
      window.removeEventListener('scroll', place, true);
      window.removeEventListener('resize', place);
    };
  }, [open]);

  return (
    <span className="popover-wrap">
      <button type="button" className="link-dotted" ref={triggerRef} onClick={onToggle}>
        {projects[0].name}
        {projects.length > 1 && ` 외 ${projects.length - 1}개`}
      </button>
      {open && (
        <div className="popover" style={{ top: position.top, left: position.left }}>
          <p className="muted small popover-title">할당 프로젝트 {projects.length}개</p>
          <ul>
            {projects.map((p) => (
              <li key={p.id}>{p.name}</li>
            ))}
          </ul>
        </div>
      )}
    </span>
  );
}

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import { formatUser } from '../utils/format.js';

/**
 * 관리자용 사용자 관리 — 계정 생성·삭제·비활성화 (SEC-003).
 * 자가 등록(회원가입)이 아니라 관리자 통제 모델의 UI다. 라우트는 RequireAdmin이
 * 감싸지만 그것은 편의일 뿐, 실제 차단은 서버의 IsAdminRole이 담당한다.
 */
export default function UsersPage() {
  const { user: me } = useAuth();
  const [users, setUsers] = useState(null);
  const [error, setError] = useState('');
  const [email, setEmail] = useState('');
  const [name, setName] = useState('');
  const [password, setPassword] = useState('');
  const [creating, setCreating] = useState(false);
  const [createError, setCreateError] = useState('');
  // 행별 액션(삭제·토글)은 한 번에 하나만 — 처리 중인 사용자 id를 기억해 잠근다.
  const [actionId, setActionId] = useState(null);
  const [actionError, setActionError] = useState('');
  // 할당 프로젝트 팝오버가 열린 사용자 id — 한 번에 하나만 연다.
  const [openProjectsFor, setOpenProjectsFor] = useState(null);

  useEffect(() => {
    if (openProjectsFor === null) return undefined;
    const closeOnOutsideClick = (event) => {
      if (!(event.target instanceof Element) || !event.target.closest('.popover-wrap')) {
        setOpenProjectsFor(null);
      }
    };
    const closeOnEscape = (event) => {
      if (event.key === 'Escape') setOpenProjectsFor(null);
    };
    document.addEventListener('mousedown', closeOnOutsideClick);
    document.addEventListener('keydown', closeOnEscape);
    return () => {
      document.removeEventListener('mousedown', closeOnOutsideClick);
      document.removeEventListener('keydown', closeOnEscape);
    };
  }, [openProjectsFor]);

  useEffect(() => {
    api('/api/users/')
      .then(setUsers)
      .catch((err) => setError(err instanceof ApiError ? err.detail : '목록을 불러오지 못했습니다.'));
  }, []);

  const handleCreate = async (event) => {
    event.preventDefault();
    setCreateError('');
    setCreating(true);
    try {
      // role은 보내지 않는다 — 보내도 서버가 무시하고 USER로 생성한다.
      const created = await api('/api/users/', { method: 'POST', body: { email, password, name } });
      setUsers((prev) => [created, ...(prev || [])]);
      setEmail('');
      setName('');
      setPassword('');
    } catch (err) {
      setCreateError(err instanceof ApiError ? err.detail : '생성에 실패했습니다.');
    } finally {
      setCreating(false);
    }
  };

  const handleToggle = async (target) => {
    setActionError('');
    setActionId(target.id);
    try {
      const updated = await api(`/api/users/${target.id}/`, {
        method: 'PATCH',
        body: { is_active: !target.is_active },
      });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : '상태 변경에 실패했습니다.');
    } finally {
      setActionId(null);
    }
  };

  const handleRename = async (target) => {
    // 폼 상태·모달 없이 처리한다 — 이 페이지의 confirm 사용과 같은 결의 최소 UI.
    const next = window.prompt('표시할 이름 (50자 이하, 비우면 이메일만 표시)', target.name || '');
    if (next === null || next.trim() === (target.name || '')) return;
    setActionError('');
    setActionId(target.id);
    try {
      const updated = await api(`/api/users/${target.id}/`, {
        method: 'PATCH',
        body: { name: next.trim() },
      });
      setUsers((prev) => prev.map((u) => (u.id === updated.id ? updated : u)));
    } catch (err) {
      setActionError(err instanceof ApiError ? err.detail : '이름 변경에 실패했습니다.');
    } finally {
      setActionId(null);
    }
  };

  const handleDelete = async (target) => {
    if (!window.confirm(`'${target.email}' 계정을 삭제할까요? 되돌릴 수 없습니다.`)) return;
    setActionError('');
    setActionId(target.id);
    try {
      await api(`/api/users/${target.id}/`, { method: 'DELETE' });
      setUsers((prev) => prev.filter((u) => u.id !== target.id));
    } catch (err) {
      setActionError(
        err instanceof ApiError && err.status === 409
          ? '활동 이력이 있어 삭제할 수 없습니다. 대신 비활성화하세요.'
          : err instanceof ApiError
            ? err.detail
            : '삭제에 실패했습니다.'
      );
    } finally {
      setActionId(null);
    }
  };

  return (
    <>
      <h1>사용자 관리</h1>

      <form className="card form-inline" onSubmit={handleCreate}>
        <input
          type="email"
          placeholder="이메일"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          required
        />
        <input
          type="text"
          placeholder="이름 (선택)"
          value={name}
          onChange={(e) => setName(e.target.value)}
          maxLength={50}
        />
        <input
          type="password"
          placeholder="비밀번호 (8자 이상)"
          value={password}
          onChange={(e) => setPassword(e.target.value)}
          autoComplete="new-password"
          required
        />
        <button type="submit" className="btn btn-primary" disabled={creating}>
          {creating ? '생성 중…' : '일반 계정 생성'}
        </button>
        <span className="muted">생성되는 계정은 일반 역할입니다. 역할 변경은 지원하지 않습니다.</span>
        {createError && <p className="form-error">{createError}</p>}
      </form>

      {error && <p className="form-error">{error}</p>}
      {actionError && <p className="form-error">{actionError}</p>}
      {users === null && !error && <p className="muted">불러오는 중…</p>}

      {users?.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>이메일</th>
              <th>역할</th>
              <th>상태</th>
              <th>할당 프로젝트</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {users.map((u) => (
              <tr key={u.id}>
                <td>{formatUser(u)}</td>
                <td className="nowrap">
                  <span className={`badge role-${u.role === 'ADMIN' ? 'admin' : 'user'}`}>
                    {u.role === 'ADMIN' ? '관리자' : '일반'}
                  </span>
                </td>
                <td className={`nowrap ${u.is_active ? '' : 'muted'}`}>
                  {u.is_active ? '활성' : '비활성'}
                </td>
                <td className="muted projects-cell">
                  {/* 표시 전용 — 할당/해제는 프로젝트 상세의 멤버 관리에서 한다 (SFR-005). */}
                  {u.projects?.length ? (
                    <ProjectsPopover
                      projects={u.projects}
                      open={openProjectsFor === u.id}
                      onToggle={() =>
                        setOpenProjectsFor(openProjectsFor === u.id ? null : u.id)
                      }
                    />
                  ) : (
                    '—'
                  )}
                </td>
                <td className="row-actions">
                  {u.id === me?.id ? (
                    <span className="muted small">본인</span>
                  ) : (
                    <>
                      <button
                        type="button"
                        className="btn-link"
                        disabled={actionId !== null}
                        onClick={() => handleRename(u)}
                      >
                        이름 수정
                      </button>
                      <button
                        type="button"
                        className="btn"
                        disabled={actionId !== null}
                        onClick={() => handleToggle(u)}
                      >
                        {actionId === u.id ? '처리 중…' : u.is_active ? '비활성화' : '활성화'}
                      </button>
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={actionId !== null || u.has_history}
                        title={
                          u.has_history
                            ? '이력이 있어 삭제할 수 없습니다. 비활성화하세요.'
                            : undefined
                        }
                        onClick={() => handleDelete(u)}
                      >
                        삭제
                      </button>
                    </>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
