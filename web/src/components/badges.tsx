import type { JobStatus, SecretStatus } from "../api/types";
import { JOB_STATUS_LABELS, SECRET_STATUS_LABELS } from "../lib/labels";
import { Badge, type Tone } from "./ui";

const SECRET_TONES: Record<SecretStatus, Tone> = { active: "green", expired: "amber", revoked: "gray", rotated: "violet" };
const JOB_TONES: Record<JobStatus, Tone> = {
  queued: "gray",
  running: "blue",
  succeeded: "green",
  failed: "red",
  cancelled: "amber",
};

export function SecretStatusBadge({ status, expired }: { status: SecretStatus; expired?: boolean }) {
  if (status === "active" && expired) return <Badge tone="amber" dot>Срок истёк</Badge>;
  return (
    <Badge tone={SECRET_TONES[status]} dot>
      {SECRET_STATUS_LABELS[status]}
    </Badge>
  );
}

export function JobStatusBadge({ status }: { status: JobStatus }) {
  return (
    <Badge tone={JOB_TONES[status]} dot>
      {JOB_STATUS_LABELS[status]}
    </Badge>
  );
}

/** Allowed / violation, and whether it is still in the current state of the source. */
export function FindingBadges({ allowed, current }: { allowed: boolean; current: boolean }) {
  return (
    <div className="flex flex-wrap gap-1">
      {allowed ? <Badge tone="green">Разрешено</Badge> : <Badge tone="red">Нарушение</Badge>}
      {current ? <Badge tone="blue">В текущем коде</Badge> : <Badge tone="gray">Только в истории</Badge>}
    </div>
  );
}
