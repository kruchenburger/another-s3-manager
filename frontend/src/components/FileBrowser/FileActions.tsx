import { ActionIcon, Group, Tooltip } from "@mantine/core";
import { Download, Eye, Link as LinkIcon, Trash2 } from "lucide-react";

export interface FileActionsProps {
  isDirectory: boolean;
  canPreview: boolean;
  onDownload?: () => void;
  onCopyUrl?: () => void;
  onPreview?: () => void;
  onDelete: () => void;
}

export function FileActions({
  isDirectory,
  canPreview,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
}: FileActionsProps) {
  return (
    <Group gap={4} wrap="nowrap">
      {!isDirectory && onDownload && (
        <Tooltip label="Download" withArrow>
          <ActionIcon variant="subtle" onClick={onDownload} aria-label="Download">
            <Download size={16} />
          </ActionIcon>
        </Tooltip>
      )}
      {!isDirectory && onCopyUrl && (
        <Tooltip label="Copy URL" withArrow>
          <ActionIcon variant="subtle" onClick={onCopyUrl} aria-label="Copy URL">
            <LinkIcon size={16} />
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
      <Tooltip label="Delete" withArrow>
        <ActionIcon variant="subtle" color="red" onClick={onDelete} aria-label="Delete">
          <Trash2 size={16} />
        </ActionIcon>
      </Tooltip>
    </Group>
  );
}
