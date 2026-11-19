import qrcode from "qrcode-generator";
import { useMemo } from "react";

/**
 * QR code drawn locally as SVG elements. The TOTP enrollment URI contains the seed, so it
 * must never be sent to an external QR service or rendered through innerHTML.
 */
export function QrCode({ value, size = 192, label }: { value: string; size?: number; label: string }) {
  const { path, count } = useMemo(() => {
    const qr = qrcode(0, "M");
    qr.addData(value);
    qr.make();
    const n = qr.getModuleCount();
    let d = "";
    for (let r = 0; r < n; r++) {
      for (let c = 0; c < n; c++) {
        if (qr.isDark(r, c)) d += `M${c + 4} ${r + 4}h1v1h-1z`;
      }
    }
    return { path: d, count: n + 8 };
  }, [value]);
  return (
    <svg
      width={size}
      height={size}
      viewBox={`0 0 ${count} ${count}`}
      role="img"
      aria-label={label}
      shapeRendering="crispEdges"
      className="rounded-lg bg-white"
    >
      <rect width={count} height={count} fill="#fff" />
      <path d={path} fill="#0f172a" />
    </svg>
  );
}
