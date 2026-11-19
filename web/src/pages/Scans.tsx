import type { JobStatus, ScanTrigger } from "../api/types";
import { ScansTable } from "../components/ScansTable";
import { PageHeader, Select } from "../components/ui";
import { useUrlFilters } from "../lib/hooks";
import { JOB_STATUS_LABELS, TRIGGER_LABELS } from "../lib/labels";

export function ScansPage() {
  const [f, set] = useUrlFilters(["status", "trigger"] as const);
  return (
    <>
      <PageHeader title="Сканы" description="Серверные сканы (вручную и по расписанию) и сканы, о которых сообщили CI и агенты." />
      <div className="mb-4 flex flex-col gap-3 sm:flex-row">
        <Select value={f.status} onChange={(e) => set("status", e.target.value)} aria-label="Статус" className="sm:w-48">
          <option value="">Все статусы</option>
          {Object.entries(JOB_STATUS_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </Select>
        <Select value={f.trigger} onChange={(e) => set("trigger", e.target.value)} aria-label="Запуск" className="sm:w-48">
          <option value="">Любой запуск</option>
          {Object.entries(TRIGGER_LABELS).map(([k, v]) => (
            <option key={k} value={k}>
              {v}
            </option>
          ))}
        </Select>
      </div>
      <ScansTable status={(f.status || undefined) as JobStatus | undefined} trigger={(f.trigger || undefined) as ScanTrigger | undefined} />
    </>
  );
}
