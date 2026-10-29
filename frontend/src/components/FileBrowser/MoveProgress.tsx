import { useState } from "react";
import {
  Affix,
  Button,
  CloseButton,
  Group,
  Loader,
  Paper,
  Progress,
  Stack,
  Text,
} from "@mantine/core";
import {
  useMoveJobs,
  resultMeaning,
  type MoveRecord,
} from "@/features/files/jobs/MoveJobsProvider";
import { formatBytes } from "@/utils/formatBytes";
import { MoveJobDetails } from "./MoveJobDetails";
import classes from "./MoveProgress.module.css";
export function MoveProgress({
  record,
  onDetails,
  onDismiss,
}: {
  record: MoveRecord;
  onDetails: () => void;
  onDismiss: () => void;
}) {
  const job = record.snapshot;
  const running = !record.unavailable && (!job || job.state === "running");
  const indeterminate =
    job?.phase === "copy" && job.total === 1 && job.done === 0;
  return (
    <Paper withBorder radius="lg" p="md" className={classes.panel}>
      <Stack gap={6} role="status" aria-live="polite" aria-atomic="true">
        <Group justify="space-between">
          <Text size="sm" fw={600}>
            Move · {record.bucket}
          </Text>
          {!running && (
            <CloseButton aria-label="Dismiss move result" onClick={onDismiss} />
          )}
        </Group>
        {record.unavailable ? (
          <Text size="sm">{record.unavailable}</Text>
        ) : job ? (
          <>
            <Text size="sm">
              {running
                ? ({
                    planning: "Planning",
                    copy: "Copying",
                    verify: "Checking source",
                    delete: "Removing originals",
                  }[job.phase] ?? job.phase)
                : resultMeaning(job)}
            </Text>
            <Text size="xs">
              Objects copied: {job.done} / {job.total}
            </Text>
            <Text size="xs">
              Bytes copied: {formatBytes(job.bytes_done)} /{" "}
              {formatBytes(job.bytes_total)}
            </Text>
            <Text size="xs">
              Originals removed: {job.removed} / {job.total}
            </Text>
            {running &&
              (indeterminate ? (
                <Group gap="xs">
                  <Loader size="xs" />
                  <Text size="sm">Copying {formatBytes(job.bytes_total)}…</Text>
                </Group>
              ) : (
                <Progress
                  aria-label="Move progress"
                  value={
                    job.total
                      ? ((job.phase === "delete" ? job.removed : job.done) /
                          job.total) *
                        100
                      : 0
                  }
                />
              ))}
          </>
        ) : (
          <Text size="sm">Waiting for progress…</Text>
        )}
      </Stack>
      {job && !record.unavailable && (
        <Button variant="subtle" size="compact-sm" mt="xs" onClick={onDetails}>
          Details
        </Button>
      )}
    </Paper>
  );
}
export function MoveJobsPanel() {
  const { jobs, dismiss, disableDeletion } = useMoveJobs();
  const [detailsId, setDetailsId] = useState<string | null>(null);
  const details = jobs.find((job) => job.job_id === detailsId);
  return (
    <>
      {jobs.length > 0 && (
        <Affix position={{ bottom: 92, right: 16 }} zIndex={130}>
          <Stack className={classes.stack} gap="xs" aria-label="Move jobs">
            {jobs.map((record) => (
              <MoveProgress
                key={record.job_id}
                record={record}
                onDetails={() => setDetailsId(record.job_id)}
                onDismiss={() => dismiss(record.job_id)}
              />
            ))}
          </Stack>
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
