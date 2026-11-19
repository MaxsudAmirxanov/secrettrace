import type { ReactNode } from "react";

import { Button, EmptyState, ErrorBanner, Spinner } from "./ui";

interface DataTableProps {
  head: ReactNode;
  children: ReactNode;
  loading?: boolean;
  error?: unknown;
  onRetry?: () => void;
  empty?: boolean;
  emptyTitle?: string;
  emptyText?: ReactNode;
  emptyIcon?: ReactNode;
  footer?: ReactNode;
}

export function DataTable({
  head,
  children,
  loading,
  error,
  onRetry,
  empty,
  emptyTitle = "Ничего не найдено",
  emptyText,
  emptyIcon,
  footer,
}: DataTableProps) {
  return (
    <div className="card overflow-hidden">
      {error ? (
        <div className="p-4">
          <ErrorBanner error={error} onRetry={onRetry} />
        </div>
      ) : loading ? (
        <div className="flex justify-center py-16 text-slate-400">
          <Spinner size={24} />
        </div>
      ) : empty ? (
        <EmptyState icon={emptyIcon} title={emptyTitle}>
          {emptyText}
        </EmptyState>
      ) : (
        <div className="overflow-x-auto">
          <table className="table-base">
            <thead>{head}</thead>
            <tbody>{children}</tbody>
          </table>
        </div>
      )}
      {footer}
    </div>
  );
}

export function LoadMore({
  hasNext,
  loading,
  onLoad,
  count,
}: {
  hasNext: boolean;
  loading: boolean;
  onLoad: () => void;
  count: number;
}) {
  if (count === 0) return null;
  return (
    <div className="flex items-center justify-between border-t border-slate-100 px-4 py-3 text-xs text-slate-500 dark:border-slate-800 dark:text-slate-400">
      <span>Показано: {count}</span>
      {hasNext && (
        <Button size="sm" onClick={onLoad} loading={loading}>
          Загрузить ещё
        </Button>
      )}
    </div>
  );
}
