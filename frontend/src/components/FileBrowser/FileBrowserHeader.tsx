import { Button, Group, SegmentedControl, Text, TextInput, Tooltip } from "@mantine/core";
import { LayoutGrid, List as ListIcon, Search, Share2, Trash2, Upload } from "lucide-react";
import { FileBreadcrumbs } from "./FileBreadcrumbs";
import type { DisplayMode } from "@/hooks/useDisplayMode";

interface FileBrowserHeaderProps {
  bucket: string;
  roleId: string;
  path: string;
  searchQuery: string;
  onSearchChange: (q: string) => void;
  mode: DisplayMode;
  onModeChange: (m: DisplayMode) => void;
  selectedCount: number;
  onBulkDelete: () => void;
  onBulkCopyUrl: () => void;
  onUploadClick: () => void;
  /** When true, bulk Delete is rendered disabled with a config-aware tooltip. */
  disableDeletion?: boolean;
  /**
   * Optional total object count (files + folders) loaded for the current
   * prefix. Renders a dimmed label next to the filter input. Omit to hide.
   */
  objectCount?: number;
}

function formatObjectCount(n: number): string {
  return n === 1 ? "1 object" : `${n} objects`;
}

export function FileBrowserHeader({
  bucket,
  roleId,
  path,
  searchQuery,
  onSearchChange,
  mode,
  onModeChange,
  selectedCount,
  onBulkDelete,
  onBulkCopyUrl,
  onUploadClick,
  disableDeletion = false,
  objectCount,
}: FileBrowserHeaderProps) {
  return (
    <Group justify="space-between" mb="md" wrap="wrap" gap="sm">
      <FileBreadcrumbs bucket={bucket} roleId={roleId} path={path} />
      <Group gap="sm">
        <TextInput
          placeholder="Filter files…"
          value={searchQuery}
          onChange={(e) => onSearchChange(e.currentTarget.value)}
          leftSection={<Search size={14} />}
          size="sm"
          style={{ minWidth: 200 }}
        />
        {typeof objectCount === "number" && (
          <Text size="sm" c="dimmed">
            {formatObjectCount(objectCount)}
          </Text>
        )}
        <SegmentedControl
          value={mode}
          onChange={(v) => onModeChange(v as DisplayMode)}
          data={[
            { value: "table", label: <ListIcon size={14} aria-label="Table view" /> },
            { value: "grid", label: <LayoutGrid size={14} aria-label="Grid view" /> },
          ]}
          size="sm"
        />
        {selectedCount > 0 && (
          <>
            <Tooltip
              label="Copy shareable links (expire in 1h, no login required)"
              withArrow
              multiline
              w={240}
            >
              <Button
                variant="light"
                leftSection={<Share2 size={14} />}
                onClick={onBulkCopyUrl}
                size="sm"
              >
                Copy URLs ({selectedCount})
              </Button>
            </Tooltip>
            <Tooltip
              label="Deletion is disabled in the server config."
              withArrow
              disabled={!disableDeletion}
            >
              <Button
                color="red"
                variant="light"
                leftSection={<Trash2 size={14} />}
                onClick={onBulkDelete}
                size="sm"
                disabled={disableDeletion}
              >
                Delete ({selectedCount})
              </Button>
            </Tooltip>
          </>
        )}
        <Button leftSection={<Upload size={14} />} onClick={onUploadClick} size="sm" data-tour="upload-btn">
          Upload
        </Button>
      </Group>
    </Group>
  );
}
