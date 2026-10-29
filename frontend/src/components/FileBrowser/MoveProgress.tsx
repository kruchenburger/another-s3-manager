import { useEffect, useRef, useState } from "react";
import {
  Affix,
  ActionIcon,
  Button,
  CloseButton,
  Group,
  Loader,
  Paper,
  Progress,
  Stack,
  Text,
  Tooltip,
} from "@mantine/core";
import {
  Check,
  ChevronDown,
  ChevronUp,
  CircleAlert,
  TriangleAlert,
} from "lucide-react";
import {
  useMoveJobs,
  resultMeaning,
  type MoveRecord,
} from "@/features/files/jobs/MoveJobsProvider";
import { formatBytes } from "@/utils/formatBytes";
import { MoveJobDetails } from "./MoveJobDetails";
import classes from "./MoveProgress.module.css";
export const SUCCESS_AUTO_DISMISS_MS = 5000;
function isRunning(record: MoveRecord) {
  return (
    !record.unavailable &&
    (!record.snapshot || record.snapshot.state === "running")
  );
}
export function MoveProgress({
  record,
  onDetails,
}: {
  record: MoveRecord;
  onDetails: () => void;
}) {
  const job = record.snapshot;
  const running = isRunning(record);
  const indeterminate =
    !job || (job.phase === "copy" && job.total === 1 && job.done === 0);
  const name =
    record.items.length === 1
      ? record.items[0].path.replace(/\/$/, "").split("/").pop()
      : `${record.items.length} items`;
  const meaning =
    record.unavailable ??
    (job
      ? running
        ? ({
            planning: "Planning",
            copy: "Copying",
            verify: "Checking source",
            delete: "Removing originals",
          }[job.phase] ?? job.phase) +
          (indeterminate && job.phase === "copy"
            ? ` ${formatBytes(job.bytes_total)}…`
            : "")
        : resultMeaning(job)
      : "Waiting for progress…");
  const warning =
    !!record.unavailable ||
    job?.state === "done_with_warnings" ||
    job?.state === "cancelled_access";
  return (
    <Stack
      component="li"
      gap={4}
      className={classes.row}
      data-move-job-id={record.job_id}
    >
      <Group gap="xs" wrap="nowrap">
        {running ? (
          <Loader size="xs" aria-label="Move running" />
        ) : warning ? (
          <TriangleAlert
            size={16}
            aria-label="Move needs attention"
            className={classes.warning}
          />
        ) : job?.state === "done" ? (
          <Check
            size={16}
            aria-label="Move complete"
            className={classes.success}
          />
        ) : (
          <CircleAlert
            size={16}
            aria-label="Move failed"
            className={classes.error}
          />
        )}
        <Tooltip label={`${name} → ${record.destination || "/"}`}>
          <Text size="sm" fw={500} truncate className={classes.label}>
            {name} → {record.destination || "/"}
          </Text>
        </Tooltip>
        {job && !record.unavailable && (
          <Button variant="subtle" size="compact-xs" onClick={onDetails}>
            Details
          </Button>
        )}
      </Group>
      <Tooltip label={meaning} multiline w={300}>
        <Text size="xs" c="dimmed" truncate>
          {meaning}
        </Text>
      </Tooltip>
      {running &&
        (indeterminate ? (
          <div
            role="progressbar"
            aria-label="Move progress"
            className={classes.indeterminate}
          />
        ) : (
          <Progress
            size={3}
            aria-label="Move progress"
            value={
              job?.total
                ? ((job.phase === "delete" ? job.removed : job.done) /
                    job.total) *
                  100
                : 0
            }
          />
        ))}
    </Stack>
  );
}
export function MoveJobsPanel() {
  const { jobs, dismiss, disableDeletion } = useMoveJobs();
  const [collapsed, setCollapsed] = useState(false);
  const [detailsId, setDetailsId] = useState<string | null>(null);
  const details = jobs.find((job) => job.job_id === detailsId);
  const running = jobs.some(isRunning);
  const clean = jobs.filter(
    (record) => !record.unavailable && record.snapshot?.state === "done",
  ).length;
  const finished = jobs.filter((record) => !isRunning(record)).length;
  const summary = running
    ? `Moving… ${finished} of ${jobs.length} done`
    : clean === jobs.length
      ? `${clean} ${clean === 1 ? "move" : "moves"} done`
      : `${clean} done · ${jobs.length - clean} needs attention`;
  const allClean = jobs.length > 0 && clean === jobs.length;
  // Polling creates fresh records and callbacks; only membership and eligibility reset the timer.
  const membership = JSON.stringify(jobs.map((record) => record.job_id));
  const latest = useRef({ jobs, dismiss });
  latest.current = { jobs, dismiss };
  useEffect(() => {
    if (!allClean) return;
    const timer = setTimeout(() => {
      const current = latest.current;
      if (
        current.jobs.every(
          (record) => !record.unavailable && record.snapshot?.state === "done",
        )
      ) {
        current.jobs.forEach((record) => current.dismiss(record.job_id));
      }
    }, SUCCESS_AUTO_DISMISS_MS);
    return () => clearTimeout(timer);
  }, [allClean, membership]);
  return (
    <>
      {jobs.length > 0 && (
        <Affix position={{ bottom: 92, right: 16 }} zIndex={130}>
          <Paper
            withBorder
            radius="lg"
            className={classes.panel}
            aria-label="Move jobs"
          >
            <Group gap={4} wrap="nowrap" p="xs">
              <Text
                size="sm"
                fw={600}
                role="status"
                aria-live="polite"
                aria-atomic="true"
                className={classes.label}
              >
                {summary}
              </Text>
              <ActionIcon
                variant="subtle"
                aria-label={
                  collapsed ? "Expand move jobs" : "Collapse move jobs"
                }
                aria-expanded={!collapsed}
                onClick={() => setCollapsed((value) => !value)}
              >
                {collapsed ? (
                  <ChevronUp size={16} />
                ) : (
                  <ChevronDown size={16} />
                )}
              </ActionIcon>
              <CloseButton
                aria-label="Dismiss move result"
                disabled={running}
                onClick={() => {
                  if (!running)
                    jobs.forEach((record) => dismiss(record.job_id));
                }}
              />
            </Group>
            {!collapsed && (
              <Stack
                component="ul"
                gap={0}
                m={0}
                p={0}
                className={classes.list}
              >
                {[...jobs].reverse().map((record) => (
                  <MoveProgress
                    key={record.job_id}
                    record={record}
                    onDetails={() => setDetailsId(record.job_id)}
                  />
                ))}
              </Stack>
            )}
          </Paper>
        </Affix>
      )}
      {details && (
        <MoveJobDetails
          key={details.job_id}
          record={details}
          onClose={() => setDetailsId(null)}
          disableDeletion={disableDeletion}
        />
      )}
    </>
  );
}
