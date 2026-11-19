import { formatBytes, formatNumber } from "./format";

const LABELS: Record<string, string> = {
  documents: "Прочитано документов",
  bytes: "Прочитано данных",
  candidates: "Кандидатов",
  matched: "Совпало с реестром",
  new_locations: "Новых мест",
  updated_locations: "Обновлённых мест",
  violations: "Нарушений",
  accepted: "Принято находок",
  ignored: "Отброшено (не в реестре)",
  no_longer_present: "Больше не в коде",
  truncated: "Обрезано по размеру",
  skipped_binary: "Пропущено бинарных",
  skipped_large: "Пропущено крупных",
  skipped_special: "Пропущено спецфайлов",
  skipped_missing: "Недоступных объектов",
  read_errors: "Ошибок чтения",
  incremental: "Режим",
};

const ORDER = Object.keys(LABELS);

export interface StatRow {
  key: string;
  label: string;
  value: string;
  emphasis?: "danger" | "muted";
}

/** Scan counters in a stable order with Russian labels; only numbers are shown. */
export function statRows(stats: Record<string, unknown>): StatRow[] {
  const keys = Object.keys(stats).filter((k) => typeof stats[k] === "number");
  keys.sort((a, b) => {
    const ia = ORDER.indexOf(a);
    const ib = ORDER.indexOf(b);
    return (ia < 0 ? 999 : ia) - (ib < 0 ? 999 : ib) || a.localeCompare(b);
  });
  return keys.map((key) => {
    const n = stats[key] as number;
    let value = formatNumber(n);
    if (key === "bytes") value = formatBytes(n);
    if (key === "incremental") value = n ? "Только новое" : "Вся история";
    const emphasis = key === "violations" && n > 0 ? "danger" : key.startsWith("skipped") || key === "truncated" ? "muted" : undefined;
    return { key, label: LABELS[key] ?? key, value, emphasis };
  });
}
