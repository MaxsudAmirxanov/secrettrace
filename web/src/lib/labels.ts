import type { CanaryHit, CanaryKind, JobStatus, Role, ScanTrigger, SecretStatus, SecretType, SourceType, TokenKind } from "../api/types";

export const SECRET_TYPE_LABELS: Record<SecretType, string> = {
  api_key: "API-ключ",
  password: "Пароль",
  token: "Токен",
  certificate: "Сертификат",
  private_key: "Приватный ключ",
  ssh_key: "SSH-ключ",
  db_connection_string: "Строка подключения к БД",
  other: "Другое",
};

export const SECRET_STATUS_LABELS: Record<SecretStatus, string> = {
  active: "Активен",
  expired: "Истёк",
  revoked: "Отозван",
  rotated: "Заменён",
};

export const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  git_repo: "Git-репозиторий",
  filesystem: "Файловая система",
  docker_image: "Docker-образ",
  k8s: "Kubernetes",
  ci_log: "Лог CI",
  app_log: "Лог приложения",
  wiki: "Wiki",
};

export const JOB_STATUS_LABELS: Record<JobStatus, string> = {
  queued: "В очереди",
  running: "Выполняется",
  succeeded: "Успешно",
  failed: "Ошибка",
  cancelled: "Отменён",
};

export const TRIGGER_LABELS: Record<ScanTrigger, string> = {
  manual: "Вручную",
  schedule: "По расписанию",
  ci: "CI",
  agent: "Агент",
};

export const ROLE_LABELS: Record<Role, string> = {
  viewer: "Наблюдатель",
  operator: "Оператор",
  admin: "Администратор",
};

export const ROLE_HINTS: Record<Role, string> = {
  viewer: "Только просмотр реестра, находок и сканов",
  operator: "Управление секретами, источниками и сканами",
  admin: "Всё, плюс пользователи, API-токены и аудит",
};

export const CANARY_KIND_LABELS: Record<CanaryKind, string> = {
  url: "Ссылка",
  api_key: "API-ключ",
};

export const CANARY_KIND_HINTS: Record<CanaryKind, string> = {
  url: "Уникальная ссылка: срабатывает, когда её кто-то откроет. Для вики, документов, закладок, писем.",
  api_key: "Фальшивый ключ с адресом сервиса для .env и конфигов: срабатывает при попытке им воспользоваться.",
};

export const CANARY_VIA_LABELS: Record<CanaryHit["via"], string> = {
  path: "путь",
  query: "параметр URL",
  bearer: "Bearer",
  basic: "Basic",
  header: "заголовок",
};

export const TOKEN_KIND_LABELS: Record<TokenKind, string> = {
  agent: "Агент",
  ci: "CI",
  automation: "Автоматизация",
};

export const API_SCOPES = [
  { id: "ingest:profile", label: "Начинать и завершать сканы" },
  { id: "ingest:match", label: "Сверять digest с реестром" },
  { id: "ingest:findings", label: "Отправлять найденные места" },
] as const;

/** Roles in privilege order, as on the server (`Viewer < Operator < Admin`). */
export const ROLE_ORDER: Role[] = ["viewer", "operator", "admin"];

export function roleAllows(have: Role, need: Role): boolean {
  return ROLE_ORDER.indexOf(have) >= ROLE_ORDER.indexOf(need);
}
