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
import { ApiError } from "@/utils/apiError";
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
export const jobsStorageKey = (username: string) =>
  `as3m:move-jobs:v1:${encodeURIComponent(username)}`;
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
function restore(username?: string): MoveRecord[] {
  if (!username) return [];
  try {
    const data: unknown = JSON.parse(
      localStorage.getItem(jobsStorageKey(username)) ?? "null",
    );
    if (
      !data ||
      typeof data !== "object" ||
      !("version" in data) ||
      data.version !== 1 ||
      !("jobs" in data) ||
      !Array.isArray(data.jobs)
    )
      return [];
    return data.jobs
      .slice(-200)
      .filter((job): job is MoveRecord => {
        if (!job || typeof job !== "object") return false;
        const j = job as Partial<MoveRecord>;
        return (
          typeof j.job_id === "string" &&
          !!j.job_id &&
          typeof j.bucket === "string" &&
          !!j.bucket &&
          typeof j.role === "string" &&
          !!j.role &&
          typeof j.destination === "string" &&
          Array.isArray(j.items) &&
          j.items.length > 0 &&
          j.items.length <= 1000 &&
          j.items.every(
            (item) =>
              typeof item?.path === "string" &&
              (item.kind === "file" || item.kind === "folder"),
          )
        );
      })
      .map(({ job_id, bucket, role, items, destination, notified }) => ({
        job_id,
        bucket,
        role,
        items,
        destination,
        notified: notified === true,
      }));
  } catch {
    return [];
  }
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
      if (error instanceof ApiError && [401, 403, 404].includes(error.status))
        return false;
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
      if (!record.notified)
        showToast({
          title: "Move result",
          message: resultMeaning(query.data),
          color: query.data.state === "done" ? "green" : "yellow",
        });
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
    if (query.error.status === 404 || query.error.status === 403) {
      update(record.job_id, {
        unavailable:
          query.error.status === 404
            ? "Result no longer available"
            : "Access to this move is no longer available",
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
  const update = useCallback(
    (id: string, patch: Partial<MoveRecord>) =>
      setJobs((prev) =>
        prev.map((job) => (job.job_id === id ? { ...job, ...patch } : job)),
      ),
    [],
  );
  const add = useCallback(
    (job: MoveRecord) =>
      setJobs((prev) =>
        prev.some((existing) => existing.job_id === job.job_id)
          ? prev
          : [...prev, job],
      ),
    [],
  );
  const dismiss = useCallback(
    (id: string) => setJobs((prev) => prev.filter((job) => job.job_id !== id)),
    [],
  );
  useEffect(() => {
    if (!username) return;
    try {
      localStorage.setItem(
        jobsStorageKey(username),
        JSON.stringify({
          version: 1,
          jobs: jobs.map(
            ({ job_id, bucket, role, items, destination, notified }) => ({
              job_id,
              bucket,
              role,
              items,
              destination,
              notified,
            }),
          ),
        }),
      );
    } catch {
      /* Storage may be unavailable; keep tracking in memory. */
    }
  }, [jobs, username]);
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
