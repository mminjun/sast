import { useEffect, useRef, useState } from 'react';
import { Link, useParams } from 'react-router-dom';

import { api, ApiError } from '../api/client.js';
import { useAuth } from '../auth/AuthContext.jsx';
import ProjectDashboard from '../components/ProjectDashboard.jsx';
import SeverityBadge from '../components/SeverityBadge.jsx';
import StatusBadge from '../components/StatusBadge.jsx';
import { formatDateTime, formatUser } from '../utils/format.js';
import {
  POLL_INTERVAL_MS, QUEUED_STALE_HINT, isInProgress, isQueuedTooLong,
} from '../utils/runStatus.js';

export default function ProjectDetailPage() {
  const { id } = useParams();
  const { isAdmin } = useAuth();
  const [project, setProject] = useState(null);
  const [runs, setRuns] = useState(null);
  // 실행별 직전 완료 대비 변화량 {run_id: {new, resolved}} — 이력으로 읽히게 하는 표시.
  const [runChanges, setRunChanges] = useState({});
  const [error, setError] = useState('');
  const [uploadError, setUploadError] = useState('');
  const [uploading, setUploading] = useState(false);
  // 커스텀 파일 버튼용 — 브라우저 기본 input 표시 대신 선택된 파일명을 직접 보여준다.
  const [selectedFileName, setSelectedFileName] = useState('');
  // 실행 요청은 큐 등록(즉시 202) — 등록 요청 중인 run id를 기억해 해당 버튼만 잠근다.
  // 실제 진행은 워커가 하고, 아래 폴링이 완료를 알아챈다.
  const [executingId, setExecutingId] = useState(null);
  // 폴링 콜백이 최신 목록과 비교하려고 쓰는 거울 — 인터벌 클로저의 runs는 낡은 값이다.
  const runsRef = useRef(null);
  runsRef.current = runs;
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
  // 분석 제외 경로 — 화면은 한 줄에 하나로 편집하고, API는 배열로 주고받는다 (관리자만 수정).
  const [excludeText, setExcludeText] = useState('');
  const [savingExclude, setSavingExclude] = useState(false);
  const [excludeError, setExcludeError] = useState('');
  const [excludeSaved, setExcludeSaved] = useState(false);

  const loadRunChanges = () => {
    // 부가 표시라 실패해도 목록은 그대로 보여준다.
    api(`/api/projects/${id}/run-changes/`)
      .then((data) => setRunChanges(data.changes || {}))
      .catch(() => {});
  };

  useEffect(() => {
    setError('');
    loadRunChanges();
    Promise.all([api(`/api/projects/${id}/`), api(`/api/projects/${id}/analysis-runs/`)])
      .then(([p, r]) => {
        setProject(p);
        setRuns(r);
        setExcludeText((p.exclude_paths || []).join('\n'));
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

  const handleSaveExclude = async (event) => {
    event.preventDefault();
    setExcludeError('');
    setExcludeSaved(false);
    setSavingExclude(true);
    // 줄 단위로 나눠 배열로 보낸다 — 항목별 검증(.. 금지, 절대 경로 금지 등)은 서버가 한다.
    const excludePaths = excludeText
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
    try {
      const updated = await api(`/api/projects/${id}/`, {
        method: 'PATCH',
        body: { exclude_paths: excludePaths },
      });
      setProject(updated);
      // 서버가 정규화(앞뒤 / 제거·중복 제거)한 값으로 되돌려 편집창을 맞춘다.
      setExcludeText((updated.exclude_paths || []).join('\n'));
      setExcludeSaved(true);
    } catch (err) {
      setExcludeError(err instanceof ApiError ? err.detail : '저장에 실패했습니다.');
    } finally {
      setSavingExclude(false);
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

  // 대기열·실행중 실행이 있는 동안 목록을 주기적으로 다시 읽는다 — 실행은 워커가 하므로
  // 화면이 완료를 알 길은 폴링뿐이다. 어떤 실행이 종료 상태로 바뀌면 변화량도 갱신한다.
  const inProgress = runs?.some((r) => isInProgress(r.status)) ?? false;
  useEffect(() => {
    if (!inProgress) return undefined;
    const timer = setInterval(() => {
      api(`/api/projects/${id}/analysis-runs/`)
        .then((next) => {
          const before = runsRef.current || [];
          const finished = before.some((prev) => {
            const now = next.find((n) => n.id === prev.id);
            return isInProgress(prev.status) && now && !isInProgress(now.status);
          });
          setRuns(next);
          if (finished) loadRunChanges();
        })
        .catch(() => {}); // 일시적 실패는 다음 폴링이 만회한다
    }, POLL_INTERVAL_MS);
    return () => clearInterval(timer);
  }, [id, inProgress]);

  // 폴링이 3초마다 다시 그리므로 "대기열에 오래 머묾" 판정도 자연히 갱신된다.
  const queuedTooLong = runs?.some((r) => isQueuedTooLong(r)) ?? false;

  const handleExecute = async (runId) => {
    setExecuteError('');
    setExecutingId(runId);
    try {
      // 응답은 큐에 등록된 상태(QUEUED). 완료·변화량은 위 폴링이 반영한다.
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

      <h2>분석 이력</h2>
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
          <span className="muted">
            {runs?.some((r) => r.status === 'SUCCEEDED')
              ? '수정한 소스를 zip으로 업로드하세요 (zip 200MB·파일 20,000개 이하). 실행하면 이전 회차와 비교해 신규·해결 항목을 보여줍니다.'
              : '분석할 소스를 zip으로 업로드하세요 (zip 200MB·파일 20,000개 이하). 실행하면 대기열에 등록되고 워커가 순서대로 진단합니다 (건당 최대 10분).'}
          </span>
          {uploadError && <p className="form-error">{uploadError}</p>}
        </form>
      )}

      {executeError && <p className="form-error">{executeError}</p>}
      {queuedTooLong && <p className="form-error">{QUEUED_STALE_HINT}</p>}
      {runs?.length === 0 && (
        <p className="muted">아직 분석 이력이 없습니다. zip을 업로드해 첫 분석을 시작하세요.</p>
      )}

      {runs?.length > 0 && (
        <table className="table">
          <thead>
            <tr>
              <th>회차</th>
              <th>파일</th>
              <th>상태</th>
              <th>결과</th>
              <th>변화</th>
              <th>업로드</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {runs.map((run, index) => (
              <tr key={run.id}>
                <td className="nowrap">
                  {/* 표시는 프로젝트 내 회차, 링크는 여전히 전역 id */}
                  <Link to={`/runs/${run.id}`}>#{run.sequence ?? run.id}</Link>
                  {/* 목록은 최신순 — 첫 행이 최신 회차다 */}
                  {index === 0 && <span className="badge badge-latest">최신</span>}
                </td>
                <td className="truncate truncate-sm" title={run.original_filename}>
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
                          // 0건도 배지 형태 유지(옅게) — 행마다 배지 개수가 달라
                          // 보이지 않게 정렬을 맞춘다.
                          <span
                            key={severity}
                            className={`badge severity-${severity.toLowerCase()} badge-dim`}
                          >
                            {label} 0
                          </span>
                        )
                      )}
                    </span>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                <td className="nowrap small">
                  {runChanges[run.id] ? (
                    <>
                      <span className={runChanges[run.id].new > 0 ? 'stat-up' : 'muted'}>
                        +{runChanges[run.id].new}
                      </span>{' '}
                      <span className={runChanges[run.id].resolved > 0 ? 'stat-down' : 'muted'}>
                        −{runChanges[run.id].resolved}
                      </span>
                    </>
                  ) : (
                    <span className="muted">—</span>
                  )}
                </td>
                {/* 완료 시각은 대부분 업로드와 같은 분이라 목록에선 생략 — 저장은
                    그대로(DAR-005)이고 실행 상세에서 확인할 수 있다. */}
                <td className="nowrap">{formatDateTime(run.created_at)}</td>
                <td className="row-actions">
                  {isAdmin && (run.status === 'PENDING' || run.status === 'FAILED') && (
                    <button
                      type="button"
                      className="btn btn-primary"
                      disabled={executingId !== null}
                      onClick={() => handleExecute(run.id)}
                    >
                      {executingId === run.id ? '등록 중…' : '실행'}
                    </button>
                  )}
                  {(run.status === 'SUCCEEDED' || run.status === 'FAILED') && (
                    <Link to={`/runs/${run.id}`} className="btn">
                      결과
                    </Link>
                  )}
                  {run.status === 'SUCCEEDED' && (
                    <Link to={`/projects/${id}/compare?target=${run.id}`} className="btn">
                      비교
                    </Link>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {/* 분석 제외 경로 — 오탐 판정(잘못 잡은 것)과 달리 "검사할 이유가 없는" 샘플·픽스처를
          스캔 자체에서 뺀다. CI 워크플로의 --exclude와 같은 개념. 읽는 사람도 무엇이 빠졌는지
          알아야 하므로 표시는 전원, 수정은 관리자만. */}
      <h2>분석 제외 경로</h2>
      {isAdmin ? (
        <form className="card exclude-editor" onSubmit={handleSaveExclude}>
          <textarea
            value={excludeText}
            onChange={(e) => {
              setExcludeText(e.target.value);
              setExcludeSaved(false);
            }}
            placeholder={'catalog/samples\ntests.py'}
            rows={4}
            spellCheck={false}
          />
          <div className="form-inline">
            <button type="submit" className="btn btn-primary" disabled={savingExclude}>
              {savingExclude ? '저장 중…' : '제외 경로 저장'}
            </button>
            {excludeSaved && <span className="muted small">저장됨 — 다음 실행부터 적용됩니다.</span>}
          </div>
          <span className="muted small">
            한 줄에 하나. <code>/</code>가 있으면 zip 루트 기준 경로(예: catalog/samples),
            없으면 어느 위치든 그 이름의 파일·폴더(예: tests.py). <code>*</code> 사용 가능.
            의도적으로 취약한 샘플·테스트 픽스처처럼 검사할 이유가 없는 경로를 빼는 용도입니다.
          </span>
          {excludeError && <p className="form-error">{excludeError}</p>}
        </form>
      ) : (
        <p className={project.exclude_paths?.length ? 'mono small' : 'muted'}>
          {project.exclude_paths?.length
            ? project.exclude_paths.join(', ')
            : '제외 경로 없음 — zip 전체를 분석합니다.'}
        </p>
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
                    <td>{formatDateTime(m.assigned_at)}</td>
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
