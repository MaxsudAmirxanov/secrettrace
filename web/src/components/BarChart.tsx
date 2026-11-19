import { useState } from "react";

import { formatDay } from "../lib/format";

/** Daily counts as an accessible SVG bar chart (no chart library). */
export function BarChart({ data, label }: { data: { day: string; count: number }[]; label: string }) {
  const [hover, setHover] = useState<number | null>(null);
  const max = Math.max(1, ...data.map((d) => d.count));
  const total = data.reduce((s, d) => s + d.count, 0);
  const w = 600;
  const h = 160;
  const pad = 4;
  const bw = (w - pad * 2) / Math.max(1, data.length);
  const active = hover === null ? null : data[hover];

  return (
    <figure className="w-full">
      <div className="mb-2 flex h-5 items-baseline justify-between text-xs text-slate-500 dark:text-slate-400">
        <span>{active ? `${formatDay(active.day)}: ${active.count}` : `Всего за период: ${total}`}</span>
        <span>макс. {max}</span>
      </div>
      <svg viewBox={`0 0 ${w} ${h}`} className="h-40 w-full" role="img" aria-label={label} preserveAspectRatio="none">
        {[0.25, 0.5, 0.75].map((f) => (
          <line key={f} x1={0} x2={w} y1={h * f} y2={h * f} className="stroke-slate-100 dark:stroke-slate-800" strokeWidth={1} />
        ))}
        {data.map((d, i) => {
          const bh = d.count === 0 ? 2 : Math.max(4, ((h - 8) * d.count) / max);
          return (
            <g key={d.day} onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)}>
              <rect x={pad + i * bw} y={0} width={bw} height={h} fill="transparent" />
              <rect
                x={pad + i * bw + bw * 0.15}
                y={h - bh}
                width={bw * 0.7}
                height={bh}
                rx={2}
                className={
                  d.count === 0
                    ? "fill-slate-200 dark:fill-slate-800"
                    : hover === i
                      ? "fill-rose-600"
                      : "fill-rose-500/80 dark:fill-rose-500/70"
                }
              >
                <title>{`${formatDay(d.day)}: ${d.count}`}</title>
              </rect>
            </g>
          );
        })}
      </svg>
      <figcaption className="mt-1 flex justify-between text-[11px] text-slate-400">
        <span>{data[0] ? formatDay(data[0].day) : ""}</span>
        <span>{data.length > 0 ? formatDay((data[data.length - 1] as { day: string }).day) : ""}</span>
      </figcaption>
    </figure>
  );
}
