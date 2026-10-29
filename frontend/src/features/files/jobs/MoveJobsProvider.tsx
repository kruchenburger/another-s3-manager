import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useRef,
  useState,
  type ReactNode,
} from "react";
import {
  useQuery,
  useQueryClient,
  type QueryClient,
} from "@tanstack/react-query";
import { useMe, meQueryKey } from "@/features/auth/hooks/useMe";
import { getJob } from "@/features/files/api/filesApi";
import type { MoveItem, MoveJob } from "@/types/api";
import { ApiError, getErrorCode } from "@/utils/apiError";
import { showToast } from "@/utils/toast";
import { MoveJobsPanel } from "@/components/FileBrowser/MoveProgress";

export interface MoveRecord {
  job_id: string;
  bucket: string;
  role: string;
  items: MoveItem[];
  destination: string;
  notified?: boolean;
  snapshot?: MoveJob;
  unavailable?: string;
}
interface JobsContext {
  jobs: MoveRecord[];
  add: (job: MoveRecord) => void;
  dismiss: (id: string) => void;
  disableDeletion: boolean;
}
const Context = createContext<JobsContext | null>(null);
const jobsPrefix = (username: string) =>
  `as3m:move-jobs:v2:${encodeURIComponent(username)}:`;
export const jobsStorageKey = (username: string, id?: string) =>
  id === undefined
    ? `as3m:move-jobs:v1:${encodeURIComponent(username)}`
    : `${jobsPrefix(username)}${encodeURIComponent(id)}`;
const dismissedPrefix = (username: string) =>
  `as3m:move-dismissed:v1:${encodeURIComponent(username)}:`;
const dismissedKey = (username: string, id: string) =>
  `${dismissedPrefix(username)}${encodeURIComponent(id)}`;
const admissionPrefix = (username: string) =>
  `as3m:move-dismiss-admission:v1:${encodeURIComponent(username)}:`;
const DISMISSAL_TTL = 60 * 60 * 1000;
const MAX_DISMISSALS = 200;
function validTimestamp(timestamp: number, now: number): boolean {
  return Number.isFinite(timestamp) && timestamp > 0 && timestamp <= now;
}
function isDismissed(username: string, id: string): boolean {
  try {
    const timestamp = Number(localStorage.getItem(dismissedKey(username, id)));
    const now = Date.now();
    return validTimestamp(timestamp, now) && now - timestamp < DISMISSAL_TTL;
  } catch {
    return false;
  }
}
function pruneMarkers(prefix: string, jobPrefix?: string): Set<string> {
  const active = new Set<string>();
  try {
    // Snapshot the keys before removing entries so enumeration cannot skip them.
    const keys: string[] = [];
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (key?.startsWith(prefix)) keys.push(key);
    }
    for (const key of keys) {
      const timestamp = Number(localStorage.getItem(key));
      const now = Date.now();
      if (validTimestamp(timestamp, now) && now - timestamp < DISMISSAL_TTL) {
        active.add(key);
      } else {
        // Remove any late writer's job before dropping its expired tombstone.
        if (jobPrefix && validTimestamp(timestamp, now))
          localStorage.removeItem(`${jobPrefix}${key.slice(prefix.length)}`);
        localStorage.removeItem(key);
      }
    }
  } catch {
    /* Storage can be unavailable; keep tracking in memory. */
  }
  return active;
}
function pruneDismissals(username: string): Set<string> {
  return pruneMarkers(dismissedPrefix(username), jobsPrefix(username));
}
function recordDismissal(username: string, id: string): boolean {
  let admissionKey: string | undefined;
  try {
    const key = dismissedKey(username, id);
    const active = pruneDismissals(username);
    if (active.has(key)) return true;
    // Never evict a live tombstone to admit another dismissal.
    if (active.size >= MAX_DISMISSALS) return false;
    // Reserve capacity under a unique key before publishing the tombstone.
    // Read reservations BEFORE committed markers: a concurrent commit can be
    // counted twice, but cannot disappear between those two counts.
    admissionKey = `${admissionPrefix(username)}${crypto.randomUUID()}`;
    localStorage.setItem(admissionKey, String(Date.now()));
    const admissions = pruneMarkers(admissionPrefix(username));
    const committed = pruneDismissals(username);
    if (committed.has(key)) return true;
    if (admissions.size + committed.size > MAX_DISMISSALS) return false;
    localStorage.setItem(key, String(Date.now()));
  } catch {
    /* Dismiss still works in memory when storage is unavailable. */
  } finally {
    if (admissionKey) {
      try {
        localStorage.removeItem(admissionKey);
      } catch {
        /* An interrupted reservation expires with the tombstone TTL. */
      }
    }
  }
  return true;
}
export function invalidateMoveFiles(
  qc: QueryClient,
  bucket: string,
  role: string,
) {
  return qc.invalidateQueries({
    predicate: ({ queryKey: k }) =>
      k[0] === "files" &&
      (k[1] === "list" || k[1] === "search") &&
      k[2] === role &&
      k[3] === bucket,
  });
}
function storedRecord(data: unknown): MoveRecord | null {
  if (!data || typeof data !== "object") return null;
  const j = data as Partial<MoveRecord>;
  if (
    typeof j.job_id !== "string" ||
    !j.job_id ||
    typeof j.bucket !== "string" ||
    !j.bucket ||
    typeof j.role !== "string" ||
    !j.role ||
    typeof j.destination !== "string" ||
    !Array.isArray(j.items) ||
    !j.items.length ||
    j.items.length > 1000 ||
    !j.items.every(
      (item) =>
        typeof item?.path === "string" &&
        (item.kind === "file" || item.kind === "folder"),
    )
  )
    return null;
  return {
    job_id: j.job_id,
    bucket: j.bucket,
    role: j.role,
    items: j.items,
    destination: j.destination,
    notified: j.notified === true,
  };
}
function readStored(key: string): MoveRecord | null {
  try {
    return storedRecord(JSON.parse(localStorage.getItem(key) ?? "null"));
  } catch {
    return null;
  }
}
function restore(username?: string): MoveRecord[] {
  if (!username) return [];
  pruneMarkers(admissionPrefix(username));
  pruneDismissals(username);
  const records = new Map<string, MoveRecord>();
  try {
    const legacy: unknown = JSON.parse(
      localStorage.getItem(jobsStorageKey(username)) ?? "null",
    );
    if (
      legacy &&
      typeof legacy === "object" &&
      "version" in legacy &&
      legacy.version === 1 &&
      "jobs" in legacy &&
      Array.isArray(legacy.jobs)
    ) {
      for (const raw of legacy.jobs.slice(-200)) {
        const record = storedRecord(raw);
        if (record && !isDismissed(username, record.job_id))
          records.set(record.job_id, record);
      }
    }
  } catch {
    /* Corrupt legacy data does not prevent reading independent jobs. */
  }
  try {
    for (let i = 0; i < localStorage.length; i++) {
      const key = localStorage.key(i);
      if (!key?.startsWith(jobsPrefix(username))) continue;
      const record = readStored(key);
      if (
        record &&
        key === jobsStorageKey(username, record.job_id) &&
        !isDismissed(username, record.job_id)
      )
        records.set(record.job_id, record);
    }
  } catch {
    /* Storage can be unavailable; keep tracking in memory. */
  }
  return [...records.values()].slice(-200);
}
function persist(username: string, job: MoveRecord) {
  try {
    if (isDismissed(username, job.job_id)) return;
    localStorage.setItem(
      jobsStorageKey(username, job.job_id),
      JSON.stringify(storedRecord(job)),
    );
  } catch {
    /* Storage can be unavailable; keep tracking in memory. */
  }
}
function terminalError(error: unknown): boolean {
  return (
    error instanceof ApiError &&
    ([401, 403, 404].includes(error.status) ||
      (error.status === 400 &&
        ["ROLE_NOT_FOUND", "ROLE_REQUIRED"].includes(
          getErrorCode(error) ?? "",
        )))
  );
}
function JobPoller({
  record,
  username,
  update,
}: {
  record: MoveRecord;
  username: string;
  update: (id: string, patch: Partial<MoveRecord>) => void;
}) {
  const qc = useQueryClient();
  const terminalHandled = useRef(false);
  const query = useQuery({
    queryKey: ["move-job", username, record.job_id],
    queryFn: () => getJob(record.job_id),
    retry: false,
    staleTime: 0,
    refetchOnWindowFocus: false,
    refetchIntervalInBackground: true,
    refetchInterval: (q) => {
      const error = q.state.error;
      if (q.state.data?.state !== undefined && q.state.data.state !== "running")
        return false;
      if (terminalError(error)) return false;
      return error
        ? Math.min(30_000, 1000 * 2 ** Math.min(q.state.errorUpdateCount, 5))
        : 1000;
    },
  });
  useEffect(() => {
    if (!query.data) return;
    const terminal = query.data.state !== "running";
    update(record.job_id, {
      snapshot: query.data,
      unavailable: undefined,
      ...(terminal ? { notified: true } : {}),
    });
    if (terminal && !terminalHandled.current) {
      terminalHandled.current = true;
      void invalidateMoveFiles(qc, record.bucket, record.role);
    }
  }, [
    query.data,
    update,
    record.job_id,
    record.notified,
    record.bucket,
    record.role,
    qc,
  ]);
  useEffect(() => {
    if (!(query.error instanceof ApiError)) return;
    if (query.error.status === 401) {
      void qc.invalidateQueries({ queryKey: meQueryKey });
      return;
    }
    if (terminalError(query.error)) {
      update(record.job_id, {
        unavailable:
          query.error.status === 404
            ? "Result no longer available"
            : query.error.status === 403
              ? "Access to this move is no longer available"
              : `Result unavailable: ${getErrorCode(query.error)}. The role is no longer available.`,
      });
      void invalidateMoveFiles(qc, record.bucket, record.role);
    }
  }, [query.error, record.job_id, record.bucket, record.role, qc, update]);
  return null;
}
export function resultMeaning(job: MoveJob): string {
  switch (job.state) {
    case "running":
      return "Move in progress.";
    case "done":
      return "Move complete. The objects are at the destination and the originals were removed.";
    case "done_with_warnings":
      return "Move finished with warnings. Some source objects or parent folders need attention; see the details.";
    case "failed_copy":
      return "Copying failed; originals are untouched. Partial copies were left at the destination.";
    case "failed_delete":
      return "A complete copy is at the destination. Some originals could not be removed and remain as duplicates.";
    case "cancelled_access":
      return "The move stopped because access or deletion permissions changed. Check the counts and details before taking further action.";
  }
}
function JobsSession({
  username,
  disableDeletion,
  children,
}: {
  username?: string;
  disableDeletion: boolean;
  children: ReactNode;
}) {
  const [jobs, setJobs] = useState(() => restore(username));
  const jobsRef = useRef(jobs);
  const replace = useCallback((next: MoveRecord[]) => {
    jobsRef.current = next;
    setJobs(next);
  }, []);
  const update = useCallback(
    (id: string, patch: Partial<MoveRecord>) => {
      const existing = jobsRef.current.find((job) => job.job_id === id);
      if (!existing) return;
      const next = { ...existing, ...patch };
      // Polling may finish after another tab dismissed this job.
      if (username && patch.notified && !existing.notified) {
        try {
          if (localStorage.getItem(jobsStorageKey(username, id)) !== null)
            persist(username, next);
        } catch {
          /* Keep progress in memory when storage is unavailable. */
        }
      }
      if (username && isDismissed(username, id)) {
        replace(jobsRef.current.filter((job) => job.job_id !== id));
        return;
      }
      replace(jobsRef.current.map((job) => (job.job_id === id ? next : job)));
    },
    [username, replace],
  );
  const add = useCallback(
    (job: MoveRecord) => {
      if (username && isDismissed(username, job.job_id)) return;
      if (jobsRef.current.some((existing) => existing.job_id === job.job_id))
        return;
      if (username) persist(username, job);
      replace([...jobsRef.current, job]);
    },
    [username, replace],
  );
  const dismiss = useCallback(
    (id: string) => {
      if (username) {
        if (!recordDismissal(username, id)) {
          showToast({
            title: "Dismiss limit reached",
            message:
              "Too many move results were dismissed in the last hour. Try again when an earlier dismissal expires.",
            color: "yellow",
          });
          return;
        }
        try {
          localStorage.removeItem(jobsStorageKey(username, id));
        } catch {
          /* Dismiss still works in memory. */
        }
      }
      replace(jobsRef.current.filter((job) => job.job_id !== id));
    },
    [username, replace],
  );
  useEffect(() => {
    if (!username) return;
    // Import v1 once, without overwriting entries already written by another tab.
    try {
      const legacy: unknown = JSON.parse(
        localStorage.getItem(jobsStorageKey(username)) ?? "null",
      );
      if (
        legacy &&
        typeof legacy === "object" &&
        "version" in legacy &&
        legacy.version === 1 &&
        "jobs" in legacy &&
        Array.isArray(legacy.jobs)
      ) {
        for (const raw of legacy.jobs.slice(-200)) {
          const job = storedRecord(raw);
          if (!job || isDismissed(username, job.job_id)) continue;
          const key = jobsStorageKey(username, job.job_id);
          if (localStorage.getItem(key) === null) {
            persist(username, job);
          }
        }
        localStorage.removeItem(jobsStorageKey(username));
      }
    } catch {
      /* Leave legacy data intact if migration cannot finish. */
    }
    const sync = (event: StorageEvent) => {
      try {
        if (event.storageArea && event.storageArea !== localStorage) return;
        if (event.key === null) {
          replace(restore(username));
          return;
        }
        if (event.key.startsWith(dismissedPrefix(username))) {
          replace(
            jobsRef.current.filter((job) => !isDismissed(username, job.job_id)),
          );
          return;
        }
        if (!event.key.startsWith(jobsPrefix(username))) return;
        // Read current storage: a queued add event may arrive after its removal.
        const record = readStored(event.key);
        if (
          !record ||
          jobsStorageKey(username, record.job_id) !== event.key ||
          isDismissed(username, record.job_id)
        ) {
          if (record && isDismissed(username, record.job_id)) {
            try {
              localStorage.removeItem(event.key);
            } catch {
              /* The tombstone still prevents restoring this stale record. */
            }
          }
          replace(
            jobsRef.current.filter(
              (job) => jobsStorageKey(username, job.job_id) !== event.key,
            ),
          );
          return;
        }
        const existing = jobsRef.current.find(
          (job) => job.job_id === record.job_id,
        );
        replace(
          existing
            ? jobsRef.current.map((job) =>
                job.job_id === record.job_id ? { ...job, ...record } : job,
              )
            : [...jobsRef.current, record],
        );
      } catch {
        /* Storage events must not interrupt the active session. */
      }
    };
    window.addEventListener("storage", sync);
    return () => window.removeEventListener("storage", sync);
  }, [username, replace]);
  return (
    <Context.Provider value={{ jobs, add, dismiss, disableDeletion }}>
      {children}
      {username &&
        jobs.map((record) => (
          <JobPoller
            key={record.job_id}
            record={record}
            username={username}
            update={update}
          />
        ))}
      {username && <MoveJobsPanel />}
    </Context.Provider>
  );
}
export function MoveJobsProvider({ children }: { children: ReactNode }) {
  const me = useMe();
  const username =
    me.error instanceof ApiError && me.error.isAuthError()
      ? undefined
      : me.data?.username;
  return (
    <JobsSession
      key={username ?? "anonymous"}
      username={username}
      disableDeletion={me.data?.disable_deletion ?? true}
    >
      {children}
    </JobsSession>
  );
}
export function useMoveJobs() {
  const context = useContext(Context);
  // Browsing can be embedded without job tracking; moves require the provider.
  return (
    context ?? {
      jobs: [],
      add: () => {
        throw new Error("MoveJobsProvider is required");
      },
      dismiss: () => {},
      disableDeletion: true,
    }
  );
}
