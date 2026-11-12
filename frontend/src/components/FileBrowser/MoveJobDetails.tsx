import { useEffect, useState } from "react";
import { Alert, Button, Modal, Stack, Text, Tooltip } from "@mantine/core";
import {
  useInfiniteQuery,
  useMutation,
  useQueryClient,
} from "@tanstack/react-query";
import { cleanupJob, getJob } from "@/features/files/api/filesApi";
import {
  invalidateMoveFiles,
  resultMeaning,
  type MoveRecord,
} from "@/features/files/jobs/MoveJobsProvider";
import { DELETION_DISABLED, ROLE_DELETION_DISABLED, MOVE_DISABLED } from "@/features/files/utils/folderOperations";
import { useRolePermissions } from "@/features/auth/hooks/useRolePermissions";
import { getErrorMessage } from "@/utils/apiError";
export function MoveJobDetails({
  record,
  onClose,
  disableDeletion: disabledByCaller = false,
}: {
  record: MoveRecord;
  onClose: () => void;
  disableDeletion?: boolean;
}) {
  const { canDelete, reason } = useRolePermissions(record.role);
  const disableDeletion = disabledByCaller || !canDelete;
  const qc = useQueryClient();
  const [loadError, setLoadError] = useState<string | null>(null);
  const job = record.snapshot;
  const pages = useInfiniteQuery({
    queryKey: ["move-failures", record.job_id],
    queryFn: ({ pageParam }) => getJob(record.job_id, pageParam),
    initialPageParam: 0,
    initialData: job ? { pages: [job], pageParams: [0] } : undefined,
    getNextPageParam: (last) => last.next_failures_offset ?? undefined,
    enabled: false,
    retry: false,
  });
  const cleanup = useMutation({
    mutationFn: () => cleanupJob(record.job_id),
    onSuccess: () => invalidateMoveFiles(qc, record.bucket, record.role),
  });
  useEffect(() => {
    if (!job) return;
    qc.setQueryData<typeof pages.data>(
      ["move-failures", record.job_id],
      (existing) =>
        existing
          ? { ...existing, pages: [job, ...existing.pages.slice(1)] }
          : { pages: [job], pageParams: [0] },
    );
  }, [job, qc, record.job_id]);
  return (
    <Modal
      opened
      onClose={onClose}
      title="Move details"
      closeButtonProps={{ "aria-label": "Close" }}
    >
      <Stack>
        <Text size="sm">Destination: {record.destination || "/"}</Text>
        {job && <Text>{resultMeaning(job)}</Text>}
        {job && (
          <Text size="sm">
            {job.failures_total} issues; {job.failures_stored} saved for
            inspection.
          </Text>
        )}
        {pages.data?.pages
          .flatMap((page) => page.failures)
          .map((failure, index) => (
            <Alert key={index} color="red">
              <Text size="sm">
                {failure.code}: {failure.message}
              </Text>
              <Text size="xs" style={{ overflowWrap: "anywhere" }}>
                {failure.phase}: {failure.key ?? "(job)"}
              </Text>
            </Alert>
          ))}
        {loadError && (
          <Alert color="red" role="alert">
            {loadError}
          </Alert>
        )}
        {pages.hasNextPage && (
          <Button
            variant="default"
            loading={pages.isFetchingNextPage}
            onClick={() => {
              setLoadError(null);
              void pages.fetchNextPage().then((result) => {
                if (result.isError) setLoadError(getErrorMessage(result.error));
              });
            }}
          >
            Load more failures
          </Button>
        )}
        {job &&
          (job.state === "failed_copy" || job.state === "cancelled_access") &&
          job.delete_started === false && !disabledByCaller && (
            <Tooltip label={reason ?? MOVE_DISABLED} disabled={!disableDeletion}>
              <Button
                variant="light"
                color="red"
                disabled={disableDeletion}
                loading={cleanup.isPending}
                onClick={() => cleanup.mutate()}
              >
                Remove partial copies
              </Button>
            </Tooltip>
          )}
        {cleanup.error && (
          <Alert color="red" role="alert">
            {getErrorMessage(cleanup.error)}
          </Alert>
        )}
        {cleanup.data && (
          <>
            <Text>
              Removed {cleanup.data.removed} partial copies.{" "}
              {cleanup.data.remaining} remain.
            </Text>
            {cleanup.data.stopped_reason && (
              <Text size="sm">
                Cleanup stopped because deleting is no longer allowed.{" "}
                {cleanup.data.stopped_reason === "DELETION_DISABLED_FOR_ROLE"
                  ? ROLE_DELETION_DISABLED.replace("<r>", record.role)
                  : cleanup.data.stopped_reason === "DELETION_DISABLED"
                    ? DELETION_DISABLED
                    : "Access to this storage location is no longer allowed."}
              </Text>
            )}
            {cleanup.data.failures.map((failure, index) => (
              <Alert key={index} color="yellow">
                {failure.code}: {failure.message} {failure.key}
              </Alert>
            ))}
          </>
        )}
      </Stack>
    </Modal>
  );
}
