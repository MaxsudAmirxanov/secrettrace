import type { Canary, CanaryCreate, CanaryKind } from "../api/types";
import type { Tone } from "../components/ui";

/** Display state: a canary that fired stays red until someone looks at it. */
export function canaryState(c: Pick<Canary, "enabled" | "hit_count">): { label: string; tone: Tone } {
  if (c.hit_count > 0) return { label: c.enabled ? "Сработала" : "Сработала, выключена", tone: "red" };
  if (!c.enabled) return { label: "Выключена", tone: "gray" };
  return { label: "Ждёт", tone: "green" };
}

/** Create-form values → request body: trimmed, empty optional fields left out. */
export function canaryBody(v: { name: string; kind: CanaryKind; plantedAt: string; memo: string }): CanaryCreate {
  const body: CanaryCreate = { name: v.name.trim(), kind: v.kind };
  if (v.plantedAt.trim()) body.planted_at = v.plantedAt.trim();
  if (v.memo.trim()) body.memo = v.memo.trim();
  return body;
}

/** Validation of the create form, or null. The server re-checks. */
export function canaryError(v: { name: string; plantedAt: string; memo: string }): string | null {
  const name = v.name.trim();
  if (!name) return "Укажите имя";
  if (name.length > 190) return "Имя: не больше 190 символов";
  if (v.plantedAt.trim().length > 500) return "«Где лежит»: не больше 500 символов";
  if (v.memo.trim().length > 2000) return "Заметка: не больше 2000 символов";
  return null;
}
