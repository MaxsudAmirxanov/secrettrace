import { Route, Routes } from "react-router-dom";

import { RequireAuth, RequireRole } from "./auth/guards";
import { Layout } from "./components/Layout";
import { AccountPage } from "./pages/Account";
import { AuditPage } from "./pages/Audit";
import { CanariesPage } from "./pages/Canaries";
import { CanaryDetailPage } from "./pages/CanaryDetail";
import { DashboardPage } from "./pages/Dashboard";
import { FindingsPage } from "./pages/Findings";
import { LoginPage } from "./pages/Login";
import { NotFoundPage } from "./pages/NotFound";
import { ScanDetailPage } from "./pages/ScanDetail";
import { ScansPage } from "./pages/Scans";
import { SecretDetailPage } from "./pages/SecretDetail";
import { SecretNewPage } from "./pages/SecretNew";
import { SecretsPage } from "./pages/Secrets";
import { SourceDetailPage } from "./pages/SourceDetail";
import { SourceNewPage } from "./pages/SourceNew";
import { SourcesPage } from "./pages/Sources";
import { TokensPage } from "./pages/Tokens";
import { UsersPage } from "./pages/Users";

export function App() {
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
        <Route index element={<DashboardPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="secrets" element={<SecretsPage />} />
        <Route
          path="secrets/new"
          element={
            <RequireRole role="operator">
              <SecretNewPage />
            </RequireRole>
          }
        />
        <Route path="secrets/:id" element={<SecretDetailPage />} />
        <Route path="sources" element={<SourcesPage />} />
        <Route
          path="sources/new"
          element={
            <RequireRole role="operator">
              <SourceNewPage />
            </RequireRole>
          }
        />
        <Route path="sources/:id" element={<SourceDetailPage />} />
        <Route path="scans" element={<ScansPage />} />
        <Route path="scans/:id" element={<ScanDetailPage />} />
        <Route path="canaries" element={<CanariesPage />} />
        <Route path="canaries/:id" element={<CanaryDetailPage />} />
        <Route
          path="tokens"
          element={
            <RequireRole role="admin">
              <TokensPage />
            </RequireRole>
          }
        />
        <Route
          path="users"
          element={
            <RequireRole role="admin">
              <UsersPage />
            </RequireRole>
          }
        />
        <Route
          path="audit"
          element={
            <RequireRole role="admin">
              <AuditPage />
            </RequireRole>
          }
        />
        <Route path="account" element={<AccountPage />} />
        <Route path="*" element={<NotFoundPage />} />
      </Route>
    </Routes>
  );
}
