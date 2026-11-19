import { Link } from "react-router-dom";

import type { Locator, SourceType } from "../api/types";
import { SOURCE_TYPE_LABELS } from "../lib/labels";
import { blobUrl, locatorPath, safeHttpUrl, shortCommit } from "../lib/locator";
import { IconExternal } from "./icons";

/** Where a finding is: source, path:line, commit — links only to plain https remotes. */
export function FindingWhere({
  uri,
  locator,
  sourceId,
  sourceName,
  sourceType,
}: {
  uri: string;
  locator: Locator;
  sourceId: string | null;
  sourceName?: string | null;
  sourceType: SourceType;
}) {
  const blob = blobUrl(uri, locator);
  const commit = shortCommit(locator);
  const repo = safeHttpUrl(uri);
  return (
    <div className="min-w-0 max-w-md">
      <p className="truncate font-mono text-[13px] text-slate-900 dark:text-slate-100" title={locatorPath(locator)}>
        {locatorPath(locator)}
      </p>
      <p className="mt-0.5 truncate text-xs text-slate-500" title={uri}>
        {sourceId ? (
          <Link to={`/sources/${sourceId}`} className="link font-normal" onClick={(e) => e.stopPropagation()}>
            {sourceName ?? uri}
          </Link>
        ) : repo ? (
          <a href={repo} target="_blank" rel="noopener noreferrer" className="link font-normal" onClick={(e) => e.stopPropagation()}>
            {uri}
          </a>
        ) : (
          <span>{uri}</span>
        )}
        <span className="text-slate-400"> · {SOURCE_TYPE_LABELS[sourceType]}</span>
        {commit && (
          <>
            {" · "}
            {blob ? (
              <a
                href={blob}
                target="_blank"
                rel="noopener noreferrer"
                className="link inline-flex items-center gap-0.5 font-mono font-normal"
                onClick={(e) => e.stopPropagation()}
                title="Открыть файл на этом коммите"
              >
                {commit}
                <IconExternal size={11} />
              </a>
            ) : (
              <span className="font-mono">{commit}</span>
            )}
          </>
        )}
        {locator.ref && <span className="text-slate-400"> · {locator.ref}</span>}
        {locator.encoding && <span className="text-slate-400"> · {locator.encoding}</span>}
      </p>
    </div>
  );
}
