import { useState } from "react";
import {
  Alert,
  Breadcrumbs,
  Button,
  Group,
  Loader,
  Modal,
  Stack,
  Text,
  TextInput,
  Tooltip,
} from "@mantine/core";
import { Folder, FolderPlus } from "lucide-react";
import type { MoveItem, MoveRequest } from "@/types/api";
import { useFiles } from "@/features/files/hooks/useFiles";
import {
  exactJoin,
  itemName,
  targetError,
  validateName,
} from "@/features/files/utils/folderOperations";
import { getErrorMessage } from "@/utils/apiError";
import { splitCrumbs } from "@/utils/pathUtils";
import { NewFolderModal } from "./NewFolderModal";

interface Props {
  bucket: string;
  role: string;
  path: string;
  items: MoveItem[];
  onClose: () => void;
  onChoose: (request: MoveRequest) => void;
  disabled?: boolean;
  busy?: boolean;
  error?: string | null;
}
export function MoveDialog({
  bucket,
  role,
  path,
  items,
  onClose,
  onChoose,
  disabled,
  busy,
  error,
}: Props) {
  const [destination, setDestination] = useState(path);
  const [name, setName] = useState(
    items.length === 1 ? itemName(items[0]) : "",
  );
  const [creating, setCreating] = useState(false);
  const [continuationError, setContinuationError] = useState<string | null>(
    null,
  );
  const listing = useFiles(bucket, role, destination);
  const chosen =
    items.length === 1 && name && name !== itemName(items[0])
      ? [{ ...items[0], new_name: name }]
      : items;
  const invalidName =
    items.length === 1 && name && name !== itemName(items[0])
      ? validateName(name)
      : null;
  const reason = targetError(chosen, destination) ?? invalidName;
  const navigate = (next: string) => {
    setDestination(next);
    setContinuationError(null);
  };
  return (
    <>
      <Modal
        opened
        onClose={onClose}
        title="Move to…"
        closeButtonProps={{ "aria-label": "Close" }}
      >
        <Stack>
          <Breadcrumbs style={{ flexWrap: "wrap" }}>
            {[{ name: bucket, path: "" }, ...splitCrumbs(destination)].map(
              (crumb) => (
                <Button
                  key={crumb.path}
                  variant="subtle"
                  size="compact-sm"
                  disabled={busy}
                  onClick={() => navigate(crumb.path)}
                >
                  {crumb.name}
                </Button>
              ),
            )}
          </Breadcrumbs>
          {items.length === 1 && (
            <TextInput
              label="New name"
              description="Optional. Choose this folder and a different name to change the name."
              disabled={busy}
              value={name}
              onChange={(event) => setName(event.currentTarget.value)}
              error={invalidName}
            />
          )}
          {listing.isPending && (
            <Loader size="sm" aria-label="Loading folders" />
          )}
          {listing.isError && !listing.isFetchNextPageError && (
            <Alert color="red" role="alert">
              {getErrorMessage(listing.error)}
              <Button variant="subtle" onClick={() => void listing.refetch()}>
                Retry
              </Button>
            </Alert>
          )}
          {listing.directories.map((folder) => {
            const next = exactJoin(destination, folder.name);
            const blocked = items.some(
              (item) =>
                item.kind === "folder" &&
                (next === item.path || next.startsWith(item.path + "/")),
            );
            return (
              <Tooltip
                key={next}
                label="A folder cannot be moved into itself or a descendant."
                disabled={!blocked}
              >
                <Button
                  variant="subtle"
                  justify="flex-start"
                  leftSection={<Folder size={16} />}
                  aria-label={`Open folder ${folder.name}`}
                  disabled={blocked || busy}
                  onClick={() => navigate(next)}
                >
                  {folder.name}
                </Button>
              </Tooltip>
            );
          })}
          {!listing.isPending &&
            !listing.isError &&
            !listing.hasNextPage &&
            listing.directories.length === 0 && (
              <Text c="dimmed">This folder has no subfolders.</Text>
            )}
          {continuationError && (
            <Alert color="red" role="alert">
              {continuationError}
            </Alert>
          )}
          {listing.hasNextPage && (
            <Button
              variant="default"
              loading={listing.isFetchingNextPage}
              onClick={() => {
                setContinuationError(null);
                void listing
                  .loadMore()
                  .catch((e: unknown) =>
                    setContinuationError(getErrorMessage(e)),
                  );
              }}
            >
              Load more
            </Button>
          )}
          {error && (
            <Alert color="red" role="alert">
              {error}
            </Alert>
          )}
          {reason && (
            <Text size="sm" c="dimmed">
              {reason}
            </Text>
          )}
          <Group justify="space-between">
            <Button
              variant="default"
              disabled={busy}
              leftSection={<FolderPlus size={16} />}
              onClick={() => setCreating(true)}
            >
              New folder
            </Button>
            <Button
              disabled={!!reason || disabled}
              loading={busy}
              onClick={() => onChoose({ items: chosen, destination })}
            >
              Move here
            </Button>
          </Group>
        </Stack>
      </Modal>
      {creating && (
        <NewFolderModal
          opened
          bucket={bucket}
          role={role}
          path={destination}
          onClose={() => setCreating(false)}
        />
      )}
    </>
  );
}
