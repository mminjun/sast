import { Navigate, Route, Routes } from 'react-router-dom';

import RequireAuth from './auth/RequireAuth.jsx';
import Layout from './components/Layout.jsx';
import CatalogPage from './pages/CatalogPage.jsx';
import LoginPage from './pages/LoginPage.jsx';
import ProjectDetailPage from './pages/ProjectDetailPage.jsx';
import ProjectListPage from './pages/ProjectListPage.jsx';
import RunDetailPage from './pages/RunDetailPage.jsx';

export default function App() {
  return (
    <Routes>
      <Route path="/login" element={<LoginPage />} />
      <Route
        element={
          <RequireAuth>
            <Layout />
          </RequireAuth>
        }
      >
        <Route path="/" element={<Navigate to="/projects" replace />} />
        <Route path="/projects" element={<ProjectListPage />} />
        <Route path="/projects/:id" element={<ProjectDetailPage />} />
        <Route path="/runs/:id" element={<RunDetailPage />} />
        <Route path="/catalog" element={<CatalogPage />} />
        <Route path="*" element={<Navigate to="/projects" replace />} />
      </Route>
    </Routes>
  );
}
