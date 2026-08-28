import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import StatusBadge from '../components/StatusBadge.jsx';

export default function ProjectDetailPage() {
  const { id } = useParams();
  const { isAdmin } = useAuth();
  const [project, setProject] = useState(null);
  const [runs, setRuns] = useState(null);
  const [error, setError] = useState('');
  const [uploadError, setUploadError] = useState('');
  const [uploading, setUploading] = useState(false);
  // 실행은 동기(최대 120초) — 실행 중인 run id를 기억해 해당 버튼만 잠근다.
  const [executingId, setExecutingId] = useState(null);
  const [executeError, setExecuteError] = useState('');
  const fileInputRef = useRef(null);

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

      <h2>분석 실행</h2>
      {isAdmin && (
        <form className="card form-inline" onSubmit={handleUpload}>
          <input type="file" accept=".zip" ref={fileInputRef} required />
          <button type="submit" className="btn btn-primary" disabled={uploading}>
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
                <td>{run.original_filename}</td>
                <td>
                  <StatusBadge status={run.status} />
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
                  {run.status === 'SUCCEEDED' && <Link to={`/runs/${run.id}`}>결과 보기</Link>}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </>
  );
}
