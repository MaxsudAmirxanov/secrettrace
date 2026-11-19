import type { SVGProps } from "react";

type IconProps = SVGProps<SVGSVGElement> & { size?: number };

function make(paths: string[], displayName: string) {
  const Icon = ({ size = 18, ...rest }: IconProps) => (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
      {...rest}
    >
      {paths.map((d) => (
        <path key={d} d={d} />
      ))}
    </svg>
  );
  Icon.displayName = displayName;
  return Icon;
}

export const IconDashboard = make(["M3 13h8V3H3z", "M13 21h8V11h-8z", "M3 21h8v-6H3z", "M13 3v6h8V3z"], "IconDashboard");
export const IconKey = make(
  ["M15.5 7.5a3.5 3.5 0 1 1-4.95 4.95L4 19v2h3v-2h2v-2h2l1.05-1.05A3.5 3.5 0 0 1 15.5 7.5z", "M16 8h.01"],
  "IconKey",
);
export const IconAlert = make(
  ["M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z", "M12 9v4", "M12 17h.01"],
  "IconAlert",
);
export const IconRepo = make(
  ["M4 19.5A2.5 2.5 0 0 1 6.5 17H20", "M6.5 2H20v20H6.5A2.5 2.5 0 0 1 4 19.5v-15A2.5 2.5 0 0 1 6.5 2z", "M9 7h6"],
  "IconRepo",
);
export const IconScan = make(
  ["M3 7V5a2 2 0 0 1 2-2h2", "M17 3h2a2 2 0 0 1 2 2v2", "M21 17v2a2 2 0 0 1-2 2h-2", "M7 21H5a2 2 0 0 1-2-2v-2", "M7 12h10"],
  "IconScan",
);
export const IconToken = make(
  ["M12 2 3 7v6c0 5 3.8 8.7 9 10 5.2-1.3 9-5 9-10V7z", "M9 12l2 2 4-4"],
  "IconToken",
);
export const IconUsers = make(
  [
    "M16 21v-2a4 4 0 0 0-4-4H6a4 4 0 0 0-4 4v2",
    "M9 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z",
    "M22 21v-2a4 4 0 0 0-3-3.87",
    "M16 3.13a4 4 0 0 1 0 7.75",
  ],
  "IconUsers",
);
export const IconAudit = make(
  ["M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8z", "M14 2v6h6", "M8 13h8", "M8 17h5"],
  "IconAudit",
);
export const IconUser = make(["M20 21v-2a4 4 0 0 0-4-4H8a4 4 0 0 0-4 4v2", "M12 11a4 4 0 1 0 0-8 4 4 0 0 0 0 8z"], "IconUser");
export const IconLogout = make(["M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4", "M16 17l5-5-5-5", "M21 12H9"], "IconLogout");
export const IconPlus = make(["M12 5v14", "M5 12h14"], "IconPlus");
export const IconSearch = make(["M11 19a8 8 0 1 0 0-16 8 8 0 0 0 0 16z", "M21 21l-4.35-4.35"], "IconSearch");
export const IconClose = make(["M18 6 6 18", "M6 6l12 12"], "IconClose");
export const IconCheck = make(["M20 6 9 17l-5-5"], "IconCheck");
export const IconCopy = make(
  ["M20 9h-9a2 2 0 0 0-2 2v9a2 2 0 0 0 2 2h9a2 2 0 0 0 2-2v-9a2 2 0 0 0-2-2z", "M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"],
  "IconCopy",
);
export const IconPlay = make(["M6 4l14 8-14 8z"], "IconPlay");
export const IconStop = make(["M6 6h12v12H6z"], "IconStop");
export const IconRefresh = make(["M21 12a9 9 0 1 1-3-6.7L21 8", "M21 3v5h-5"], "IconRefresh");
export const IconTrash = make(["M3 6h18", "M8 6V4h8v2", "M19 6l-1 14H6L5 6"], "IconTrash");
export const IconEdit = make(["M12 20h9", "M16.5 3.5a2.1 2.1 0 0 1 3 3L7 19l-4 1 1-4z"], "IconEdit");
export const IconExternal = make(["M18 13v6a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V8a2 2 0 0 1 2-2h6", "M15 3h6v6", "M10 14 21 3"], "IconExternal");
export const IconMenu = make(["M3 6h18", "M3 12h18", "M3 18h18"], "IconMenu");
export const IconSun = make(
  ["M12 17a5 5 0 1 0 0-10 5 5 0 0 0 0 10z", "M12 1v2", "M12 21v2", "M4.2 4.2l1.4 1.4", "M18.4 18.4l1.4 1.4", "M1 12h2", "M21 12h2", "M4.2 19.8l1.4-1.4", "M18.4 5.6l1.4-1.4"],
  "IconSun",
);
export const IconMoon = make(["M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"], "IconMoon");
export const IconShield = make(["M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"], "IconShield");
export const IconLock = make(["M5 11h14v10H5z", "M8 11V7a4 4 0 0 1 8 0v4"], "IconLock");
export const IconEye = make(["M1 12s4-8 11-8 11 8 11 8-4 8-11 8S1 12 1 12z", "M12 15a3 3 0 1 0 0-6 3 3 0 0 0 0 6z"], "IconEye");
export const IconEyeOff = make(
  ["M17.9 17.9A10.4 10.4 0 0 1 12 20c-7 0-11-8-11-8a18.5 18.5 0 0 1 5.1-5.9", "M9.9 4.2A9.1 9.1 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.2 3.2", "M1 1l22 22", "M14.1 14.1a3 3 0 1 1-4.2-4.2"],
  "IconEyeOff",
);
export const IconClock = make(["M12 22a10 10 0 1 0 0-20 10 10 0 0 0 0 20z", "M12 6v6l4 2"], "IconClock");
export const IconChevronRight = make(["M9 18l6-6-6-6"], "IconChevronRight");
export const IconFilter = make(["M22 3H2l8 9.5V19l4 2v-8.5z"], "IconFilter");
