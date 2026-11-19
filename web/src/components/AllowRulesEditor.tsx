import type { AllowRule, SourceType } from "../api/types";
import { SOURCE_TYPE_LABELS } from "../lib/labels";
import { IconPlus, IconTrash } from "./icons";
import { Button, Field, Input, Select } from "./ui";

export const emptyRule = (): AllowRule => ({ uri_pattern: "", source_type: null, path_pattern: "", environment: "", comment: "" });

/** Drop empty optional fields and server-assigned ids before sending. */
export function cleanRules(rules: AllowRule[]): AllowRule[] {
  return rules.map((r) => {
    const out: AllowRule = { uri_pattern: r.uri_pattern.trim() };
    if (r.source_type) out.source_type = r.source_type;
    if (r.path_pattern?.trim()) out.path_pattern = r.path_pattern.trim();
    if (r.environment?.trim()) out.environment = r.environment.trim();
    if (r.comment?.trim()) out.comment = r.comment.trim();
    return out;
  });
}

export function rulesError(rules: AllowRule[]): string | null {
  return rules.some((r) => !r.uri_pattern.trim()) ? "У каждого правила должен быть шаблон URI" : null;
}

export function AllowRulesEditor({ rules, onChange }: { rules: AllowRule[]; onChange: (r: AllowRule[]) => void }) {
  const update = (i: number, patch: Partial<AllowRule>) => onChange(rules.map((r, j) => (j === i ? { ...r, ...patch } : r)));
  return (
    <div className="space-y-3">
      {rules.length === 0 && (
        <p className="text-sm text-slate-500 dark:text-slate-400">
          Правил нет: любое обнаружение секрета будет нарушением.
        </p>
      )}
      {rules.map((r, i) => (
        <div key={i} className="rounded-lg border border-slate-200 p-4 dark:border-slate-700">
          <div className="grid gap-3 sm:grid-cols-2">
            <Field label="Шаблон URI" required hint="Glob: * — внутри сегмента, ** — через «/»" className="sm:col-span-2">
              {(id, d) => (
                <Input
                  id={id}
                  aria-describedby={d}
                  value={r.uri_pattern}
                  placeholder="https://git.example/infra/**"
                  onChange={(e) => update(i, { uri_pattern: e.target.value })}
                  maxLength={512}
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label="Путь в источнике">
              {(id) => (
                <Input
                  id={id}
                  value={r.path_pattern ?? ""}
                  placeholder="k8s/sealed/**"
                  onChange={(e) => update(i, { path_pattern: e.target.value })}
                  maxLength={512}
                  spellCheck={false}
                />
              )}
            </Field>
            <Field label="Тип источника">
              {(id) => (
                <Select
                  id={id}
                  value={r.source_type ?? ""}
                  onChange={(e) => update(i, { source_type: (e.target.value || null) as SourceType | null })}
                >
                  <option value="">Любой</option>
                  {Object.entries(SOURCE_TYPE_LABELS).map(([k, v]) => (
                    <option key={k} value={k}>
                      {v}
                    </option>
                  ))}
                </Select>
              )}
            </Field>
            <Field label="Окружение">
              {(id) => (
                <Input
                  id={id}
                  value={r.environment ?? ""}
                  placeholder="prod"
                  onChange={(e) => update(i, { environment: e.target.value })}
                  maxLength={64}
                />
              )}
            </Field>
            <Field label="Комментарий">
              {(id) => (
                <Input
                  id={id}
                  value={r.comment ?? ""}
                  placeholder="Зашифровано sealed-secrets"
                  onChange={(e) => update(i, { comment: e.target.value })}
                  maxLength={500}
                />
              )}
            </Field>
          </div>
          <div className="mt-3 flex justify-end">
            <Button size="sm" variant="ghost" icon={<IconTrash size={14} />} onClick={() => onChange(rules.filter((_, j) => j !== i))}>
              Удалить правило
            </Button>
          </div>
        </div>
      ))}
      <Button size="sm" icon={<IconPlus size={14} />} onClick={() => onChange([...rules, emptyRule()])} disabled={rules.length >= 100}>
        Добавить правило
      </Button>
    </div>
  );
}
