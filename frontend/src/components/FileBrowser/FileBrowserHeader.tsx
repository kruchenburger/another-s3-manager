import { Button, Group, SegmentedControl, TextInput } from "@mantine/core";
import { LayoutGrid, Link as LinkIcon, List as ListIcon, Search, Trash2, Upload } from "lucide-react";
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
            <Button
              variant="light"
              leftSection={<LinkIcon size={14} />}
              onClick={onBulkCopyUrl}
              size="sm"
            >
              Copy URLs ({selectedCount})
            </Button>
            <Button
              color="red"
              variant="light"
              leftSection={<Trash2 size={14} />}
              onClick={onBulkDelete}
              size="sm"
            >
              Delete ({selectedCount})
            </Button>
          </>
        )}
        <Button leftSection={<Upload size={14} />} onClick={onUploadClick} size="sm" data-tour="upload-btn">
          Upload
        </Button>
      </Group>
    </Group>
  );
}
