import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import ProjectDashboard from '../components/ProjectDashboard.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { formatUser } from '../utils/format.js';

export default function ProjectDetailPage() {
  const { id } = useParams();
  const { isAdmin } = useAuth();
  const [project, setProject] = useState(null);
  const [runs, setRuns] = useState(null);
  const [error, setError] = useState('');
  const [uploadError, setUploadError] = useState('');
  const [uploading, setUploading] = useState(false);
  // 커스텀 파일 버튼용 — 브라우저 기본 input 표시 대신 선택된 파일명을 직접 보여준다.
  const [selectedFileName, setSelectedFileName] = useState('');
  // 실행은 동기(최대 120초) — 실행 중인 run id를 기억해 해당 버튼만 잠근다.
  const [executingId, setExecutingId] = useState(null);
  const [executeError, setExecuteError] = useState('');
  const fileInputRef = useRef(null);
  // 멤버 할당·해제는 관리자 전용 — 서버의 members API도 IsAdminRole로 닫혀 있어
  // 일반 사용자는 조회 요청 자체를 보내지 않는다 (SFR-005, SEC-003).
  const [members, setMembers] = useState(null);
  const [allUsers, setAllUsers] = useState(null);
  const [memberError, setMemberError] = useState('');
  const [addUserId, setAddUserId] = useState('');
  const [addingMember, setAddingMember] = useState(false);
  const [removingId, setRemovingId] = useState(null);

  useEffect(() => {
    setError('');
    Promise.all([api(`/api/projects/${id}/`), api(`/api/projects/${id}/analysis-runs/`)])
      .then(([p, r]) => {
        setProject(p);
        setRuns(r);
      })
      .catch((err) => {
        // 미할당·미존재 프로젝트는 서버가 동일한 404를 준다 (SEC-006) — 구분하지 않는다.
        setError(
          err instanceof ApiError && err.status === 404
            ? '프로젝트를 찾을 수 없습니다.'
            : '프로젝트를 불러오지 못했습니다.'
        );
      });
  }, [id]);

  useEffect(() => {
    if (!isAdmin) return;
    setMemberError('');
    Promise.all([api(`/api/projects/${id}/members/`), api('/api/users/')])
      .then(([m, u]) => {
        setMembers(m);
        setAllUsers(u);
      })
      .catch((err) =>
        setMemberError(err instanceof ApiError ? err.detail : '멤버 목록을 불러오지 못했습니다.')
      );
  }, [id, isAdmin]);

  const handleAddMember = async (event) => {
    event.preventDefault();
    if (!addUserId) return;
    setMemberError('');
    setAddingMember(true);
    try {
      const membership = await api(`/api/projects/${id}/members/`, {
        method: 'POST',
        body: { user_id: Number(addUserId) },
      });
      setMembers((prev) => [membership, ...(prev || [])]);
      setAddUserId('');
    } catch (err) {
      setMemberError(err instanceof ApiError ? err.detail : '할당에 실패했습니다.');
    } finally {
      setAddingMember(false);
    }
  };

  const handleRemoveMember = async (userId) => {
    setMemberError('');
    setRemovingId(userId);
    try {
      await api(`/api/projects/${id}/members/${userId}/`, { method: 'DELETE' });
      setMembers((prev) => prev.filter((m) => m.user.id !== userId));
    } catch (err) {
      setMemberError(err instanceof ApiError ? err.detail : '해제에 실패했습니다.');
    } finally {
      setRemovingId(null);
    }
  };

  const handleUpload = async (event) => {
    event.preventDefault();
    const file = fileInputRef.current?.files?.[0];
    if (!file) return;
    setUploadError('');
    setUploading(true);
    try {
      const form = new FormData();
      form.append('file', file);
      const run = await api(`/api/projects/${id}/analysis-runs/`, { method: 'POST', form });
      setRuns((prev) => [run, ...(prev || [])]);
      fileInputRef.current.value = '';
      setSelectedFileName('');
    } catch (err) {
      setUploadError(err instanceof ApiError ? err.detail : '업로드에 실패했습니다.');
    } finally {
      setUploading(false);
    }
  };

  const handleExecute = async (runId) => {
    setExecuteError('');
    setExecutingId(runId);
    try {
      const updated = await api(`/api/analysis-runs/${runId}/execute/`, { method: 'POST' });
      setRuns((prev) => prev.map((r) => (r.id === updated.id ? updated : r)));
    } catch (err) {
      setExecuteError(err instanceof ApiError ? err.detail : '실행 요청에 실패했습니다.');
    } finally {
      setExecutingId(null);
    }
  };

  if (error) return <p className="form-error">{error}</p>;
  if (!project) return <p className="muted">불러오는 중…</p>;

  return (
    <>
      <p className="breadcrumb">
        <Link to="/projects">프로젝트</Link> / {project.name}
      </p>
      <h1>{project.name}</h1>
      {project.description && <p className="muted">{project.description}</p>}

      {/* 실행 0개는 아래 실행 목록의 빈 안내로 충분 — 대시보드는 실행이 있을 때만. */}
      {runs?.length > 0 && <ProjectDashboard projectId={id} runs={runs} />}

      <h2>분석 실행</h2>
      {isAdmin && (
        <form className="card form-inline" onSubmit={handleUpload}>
          <label className="btn file-pick">
            파일 선택
            <input
              type="file"
              accept=".zip"
              ref={fileInputRef}
              className="visually-hidden"
              onChange={(e) => setSelectedFileName(e.target.files?.[0]?.name || '')}
              required
            />
          </label>
          <span className={selectedFileName ? 'mono small' : 'muted small'}>
            {selectedFileName || '선택된 파일 없음'}
          </span>
          <button
            type="submit"
            className="btn btn-primary"
            disabled={uploading || !selectedFileName}
          >
            {uploading ? '업로드 중…' : 'zip 업로드'}
          </button>
          <span className="muted">소스 zip (50MB 이하). 업로드 후 실행 버튼으로 분석합니다.</span>
          {uploadError && <p className="form-error">{uploadError}</p>}
        </form>
      )}

      {executeError && <p className="form-error">{executeError}</p>}
      {runs?.length === 0 && <p className="muted">분석 실행이 없습니다.</p>}

      {runs?.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>#</th>
              <th>파일</th>
              <th>상태</th>
              <th>결과</th>
              <th>업로드</th>
              <th>완료</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run) => (
              <tr key={run.id}>
                <td>
                  <Link to={`/runs/${run.id}`}>{run.id}</Link>
                </td>
                <td className="truncate" title={run.original_filename}>
                  {run.original_filename}
                </td>
                <td>
                  <StatusBadge status={run.status} />
                </td>
                <td>
                  {run.status === 'SUCCEEDED' && run.severity_counts ? (
                    <span className="severity-counts">
                      {[
                        ['HIGH', '높음', run.severity_counts.high],
                        ['MEDIUM', '보통', run.severity_counts.medium],
                        ['LOW', '낮음', run.severity_counts.low],
                      ].map(([severity, label, count]) =>
                        count > 0 ? (
                          <SeverityBadge key={severity} severity={severity} label={`${label} ${count}`} />
                        ) : (
                          <span key={severity} className="muted small">
                            {label} 0
                          </span>
                        )
                      )}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td>{new Date(run.created_at).toLocaleString('ko-KR')}</td>
                <td>{run.finished_at ? new Date(run.finished_at).toLocaleString('ko-KR') : '—'}</td>
                <td className="row-actions">
                  {isAdmin && (run.status === 'PENDING' || run.status === 'FAILED') && (
                    <button
                      type="button"
                      className="btn"
                      disabled={executingId !== null}
                      onClick={() => handleExecute(run.id)}
                    >
                      {executingId === run.id ? '분석 중… (최대 2분)' : '실행'}
                    </button>
                  )}
                  {(run.status === 'SUCCEEDED' || run.status === 'FAILED') && (
                    <Link to={`/runs/${run.id}`}>결과 보기</Link>
                  )}
                  {run.status === 'SUCCEEDED' && (
                    <Link to={`/projects/${id}/compare?target=${run.id}`}>이전 실행과 비교</Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {isAdmin && (
        <>
          <h2>멤버</h2>
          <form className="card form-inline" onSubmit={handleAddMember}>
            <select
              value={addUserId}
              onChange={(e) => setAddUserId(e.target.value)}
              required
            >
              <option value="">할당할 사용자 선택</option>
              {allUsers
                ?.filter(
                  // admin은 스코프상 전체 조회라 할당이 무의미 — 일반 계정만 후보로.
                  (u) =>
                    u.role !== 'ADMIN' &&
                    u.is_active &&
                    !members?.some((m) => m.user.id === u.id)
                )
                .map((u) => (
                  <option key={u.id} value={u.id}>
                    {formatUser(u)}
                  </option>
                ))}
            </select>
            <button type="submit" className="btn btn-primary" disabled={addingMember || !addUserId}>
              {addingMember ? '할당 중…' : '할당'}
            </button>
            <span className="muted">할당된 사용자만 이 프로젝트를 조회할 수 있습니다.</span>
            {memberError && <p className="form-error">{memberError}</p>}
          </form>

          {members?.length === 0 && <p className="muted">할당된 사용자가 없습니다.</p>}
          {members?.length > 0 && (
            <table className="table">
              <thead>
                <tr>
                  <th>이메일</th>
                  <th>할당자</th>
                  <th>할당일</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {members.map((m) => (
                  <tr key={m.id}>
                    <td>{formatUser(m.user)}</td>
                    <td className="muted">{formatUser(m.assigned_by)}</td>
                    <td>{new Date(m.assigned_at).toLocaleString('ko-KR')}</td>
                    <td className="row-actions">
                      <button
                        type="button"
                        className="btn btn-danger"
                        disabled={removingId !== null}
                        onClick={() => handleRemoveMember(m.user.id)}
                      >
                        {removingId === m.user.id ? '해제 중…' : '해제'}
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </>
      )}
    </>
  );
}
