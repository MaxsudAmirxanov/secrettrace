import { type ReactNode, useEffect, useState } from "react";
import { NavLink, Outlet, useLocation } from "react-router-dom";

import { useAuth, useUser } from "../auth/AuthContext";
import type { Role } from "../api/types";
import { ROLE_LABELS } from "../lib/labels";
import { useTheme } from "../lib/theme";
import {
  IconAlert,
  IconAudit,
  IconBell,
  IconDashboard,
  IconKey,
  IconLogout,
  IconMenu,
  IconMoon,
  IconRepo,
  IconScan,
  IconShield,
  IconSun,
  IconToken,
  IconUser,
  IconUsers,
} from "./icons";
import { cx } from "./ui";

interface NavEntry {
  to: string;
  label: string;
  icon: ReactNode;
  role: Role;
  end?: boolean;
}

const MAIN: NavEntry[] = [
  { to: "/", label: "Обзор", icon: <IconDashboard />, role: "viewer", end: true },
  { to: "/findings", label: "Находки", icon: <IconAlert />, role: "viewer" },
  { to: "/secrets", label: "Реестр секретов", icon: <IconKey />, role: "viewer" },
  { to: "/sources", label: "Источники", icon: <IconRepo />, role: "viewer" },
  { to: "/scans", label: "Сканы", icon: <IconScan />, role: "viewer" },
  { to: "/canaries", label: "Ловушки", icon: <IconBell />, role: "viewer" },
];

const ADMIN: NavEntry[] = [
  { to: "/tokens", label: "API-токены", icon: <IconToken />, role: "admin" },
  { to: "/users", label: "Пользователи", icon: <IconUsers />, role: "admin" },
  { to: "/audit", label: "Журнал аудита", icon: <IconAudit />, role: "admin" },
];

function NavList({ items }: { items: NavEntry[] }) {
  const { can } = useAuth();
  return (
    <ul className="space-y-0.5">
      {items
        .filter((i) => can(i.role))
        .map((i) => (
          <li key={i.to}>
            <NavLink to={i.to} end={i.end} className={({ isActive }) => cx("nav-item", isActive && "active")}>
              {i.icon}
              {i.label}
            </NavLink>
          </li>
        ))}
    </ul>
  );
}

function Sidebar({ onNavigate }: { onNavigate?: () => void }) {
  const user = useUser();
  const { can, logout } = useAuth();
  return (
    <div className="flex h-full flex-col bg-slate-900 text-slate-300 dark:bg-slate-950" onClick={onNavigate}>
      <div className="flex h-16 items-center gap-2.5 px-5">
        <span className="flex h-8 w-8 items-center justify-center rounded-lg bg-brand-600 text-white">
          <IconShield size={18} />
        </span>
        <span className="text-[15px] font-semibold tracking-tight text-white">SecretTrace</span>
      </div>
      <nav className="flex-1 space-y-6 overflow-y-auto px-3 py-2" aria-label="Основная навигация">
        <NavList items={MAIN} />
        {can("admin") && (
          <div>
            <p className="mb-1.5 px-3 text-[11px] font-semibold uppercase tracking-wider text-slate-500">Администрирование</p>
            <NavList items={ADMIN} />
          </div>
        )}
      </nav>
      <div className="border-t border-white/10 p-3">
        <NavLink to="/account" className={({ isActive }) => cx("nav-item", isActive && "active")}>
          <IconUser />
          <span className="min-w-0 flex-1">
            <span className="block truncate text-white">{user.username}</span>
            <span className="block text-xs font-normal text-slate-400">{ROLE_LABELS[user.role]}</span>
          </span>
        </NavLink>
        <button type="button" className="nav-item mt-0.5 w-full" onClick={() => void logout()}>
          <IconLogout />
          Выйти
        </button>
      </div>
    </div>
  );
}

export function Layout() {
  const [open, setOpen] = useState(false);
  const [theme, toggleTheme] = useTheme();
  const location = useLocation();
  useEffect(() => setOpen(false), [location.pathname]);

  return (
    <div className="min-h-screen lg:pl-64">
      <a href="#main" className="sr-only focus:not-sr-only focus:fixed focus:left-2 focus:top-2 focus:z-50 focus:rounded focus:bg-white focus:px-3 focus:py-2">
        К содержимому
      </a>
      <aside className="fixed inset-y-0 left-0 z-30 hidden w-64 lg:block">
        <Sidebar />
      </aside>
      {open && (
        <div className="fixed inset-0 z-40 lg:hidden" role="dialog" aria-modal="true" aria-label="Меню">
          <div className="absolute inset-0 bg-slate-900/60" onClick={() => setOpen(false)} aria-hidden="true" />
          <div className="absolute inset-y-0 left-0 w-64 shadow-xl">
            <Sidebar onNavigate={() => setOpen(false)} />
          </div>
        </div>
      )}
      <header className="sticky top-0 z-20 flex h-14 items-center gap-3 border-b border-slate-200 bg-white/80 px-4 backdrop-blur dark:border-slate-800 dark:bg-slate-950/80 sm:px-6">
        <button type="button" className="btn btn-ghost -ml-2 p-2 lg:hidden" onClick={() => setOpen(true)} aria-label="Открыть меню">
          <IconMenu />
        </button>
        <div className="flex-1" />
        <button
          type="button"
          className="btn btn-ghost p-2"
          onClick={toggleTheme}
          aria-label={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
          title={theme === "dark" ? "Светлая тема" : "Тёмная тема"}
        >
          {theme === "dark" ? <IconSun /> : <IconMoon />}
        </button>
      </header>
      <main id="main" className="mx-auto max-w-7xl px-4 py-6 sm:px-6 lg:px-8 lg:py-8">
        <Outlet />
      </main>
    </div>
  );
}
