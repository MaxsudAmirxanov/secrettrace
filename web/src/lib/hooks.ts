import { useCallback, useEffect, useMemo, useState } from "react";
import { useSearchParams } from "react-router-dom";

export function useDebounced<T>(value: T, ms = 300): T {
  const [v, setV] = useState(value);
  useEffect(() => {
    const t = window.setTimeout(() => setV(value), ms);
    return () => window.clearTimeout(t);
  }, [value, ms]);
  return v;
}

/** Filters kept in the URL query string, so a filtered view can be shared or bookmarked. */
export function useUrlFilters<K extends string>(keys: readonly K[]) {
  const [params, setParams] = useSearchParams();
  const values = useMemo(() => {
    const out = {} as Record<K, string>;
    for (const k of keys) out[k] = params.get(k) ?? "";
    return out;
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [params, keys.join(",")]);
  // One navigation per change: consecutive setSearchParams calls would overwrite each other.
  const setMany = useCallback(
    (patch: Partial<Record<K, string>>) => {
      setParams(
        (prev) => {
          const p = new URLSearchParams(prev);
          for (const [k, v] of Object.entries(patch) as [K, string | undefined][]) {
            if (v) p.set(k, v);
            else p.delete(k);
          }
          return p;
        },
        { replace: true },
      );
    },
    [setParams],
  );
  const set = useCallback((k: K, v: string) => setMany({ [k]: v } as Partial<Record<K, string>>), [setMany]);
  return [values, set, setMany] as const;
}

/** `"true"`/`"false"` → boolean, anything else → undefined. */
export const boolParam = (v: string): boolean | undefined => (v === "true" ? true : v === "false" ? false : undefined);

/** A text input whose debounced value is committed (e.g. to the URL). */
export function useSyncedSearch(value: string, commit: (v: string) => void, ms = 300) {
  const [text, setText] = useState(value);
  const debounced = useDebounced(text, ms);
  useEffect(() => {
    if (debounced !== value) commit(debounced);
    // Only the debounced input drives commits; `value` changes come from the URL.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [debounced]);
  return [text, setText] as const;
}
