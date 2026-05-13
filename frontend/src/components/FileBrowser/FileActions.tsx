import { ActionIcon, Group, Tooltip } from "@mantine/core";
import { Download, Eye, Share2, Trash2 } from "lucide-react";

export interface FileActionsProps {
  isDirectory: boolean;
  canPreview: boolean;
  /** Display name of the file — used for accessible Download button label. */
  filename?: string;
  onDownload?: () => void;
  onCopyUrl?: () => void;
  onPreview?: () => void;
  onDelete: () => void;
  /** When true, Delete is rendered disabled with a config-aware tooltip. */
  disabled?: boolean;
}

const DISABLED_DELETE_LABEL = "Deletion is disabled in the server config.";

export function FileActions({
  isDirectory,
  canPreview,
  filename,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
  disabled = false,
}: FileActionsProps) {
  const downloadLabel = filename ? `Download ${filename}` : "Download";
  return (
    <Group gap={4} wrap="nowrap">
      {!isDirectory && onDownload && (
        <Tooltip label="Download" withArrow>
          <ActionIcon variant="subtle" onClick={onDownload} aria-label={downloadLabel}>
            <Download size={16} />
          </ActionIcon>
        </Tooltip>
      )}
      {!isDirectory && onCopyUrl && (
        <Tooltip
          label="Copy shareable link (expires in 1h, no login required)"
          withArrow
          multiline
          w={240}
        >
          <ActionIcon variant="subtle" onClick={onCopyUrl} aria-label="Copy URL">
            <Share2 size={16} />
          </ActionIcon>
        </Tooltip>
      )}
      {!isDirectory && canPreview && onPreview && (
        <Tooltip label="Preview" withArrow>
          <ActionIcon variant="subtle" onClick={onPreview} aria-label="Preview">
            <Eye size={16} />
          </ActionIcon>
        </Tooltip>
      )}
      <Tooltip label={disabled ? DISABLED_DELETE_LABEL : "Delete"} withArrow>
        <ActionIcon
          variant="subtle"
          color="red"
          onClick={onDelete}
          aria-label="Delete"
          disabled={disabled}
          data-disabled-reason={disabled ? DISABLED_DELETE_LABEL : undefined}
        >
          <Trash2 size={16} />
        </ActionIcon>
      </Tooltip>
    </Group>
  );
}
