import { ActionIcon, Menu } from "@mantine/core";
import { Download, Eye, MoreVertical, Share2, Trash2 } from "lucide-react";

interface FileRowActionsMenuProps {
  isDirectory: boolean;
  canPreview: boolean;
  filename: string;
  onDownload: () => void;
  onCopyUrl: () => void;
  onPreview: () => void;
  onDelete: () => void;
  /** When true, Delete is rendered disabled (deletion off in server config). */
  disabled?: boolean;
}

/** Compact touch variant of FileActions: a single ⋮ trigger + menu.
 * Rendered below the sm breakpoint only (see FileRow) — four inline icons
 * would starve the Name column on phones. Desktop keeps the inline
 * hover-reveal icons; the per-link TTL override (a right-click affordance)
 * is desktop-only, so the menu's Copy URL always uses the default TTL. */
export function FileRowActionsMenu({
  isDirectory,
  canPreview,
  filename,
  onDownload,
  onCopyUrl,
  onPreview,
  onDelete,
  disabled = false,
}: FileRowActionsMenuProps) {
  return (
    <Menu position="bottom-end" withinPortal>
      <Menu.Target>
        <ActionIcon
          variant="subtle"
          color="gray"
          aria-label={`Actions for ${filename}`}
        >
          <MoreVertical size={16} />
        </ActionIcon>
      </Menu.Target>
      <Menu.Dropdown>
        {!isDirectory && (
          <Menu.Item leftSection={<Download size={14} />} onClick={onDownload}>
            Download
          </Menu.Item>
        )}
        {!isDirectory && (
          <Menu.Item leftSection={<Share2 size={14} />} onClick={onCopyUrl}>
            Copy URL
          </Menu.Item>
        )}
        {!isDirectory && canPreview && (
          <Menu.Item leftSection={<Eye size={14} />} onClick={onPreview}>
            Preview
          </Menu.Item>
        )}
        <Menu.Item
          color="red"
          leftSection={<Trash2 size={14} />}
          onClick={onDelete}
          disabled={disabled}
        >
          Delete
        </Menu.Item>
      </Menu.Dropdown>
    </Menu>
  );
}
