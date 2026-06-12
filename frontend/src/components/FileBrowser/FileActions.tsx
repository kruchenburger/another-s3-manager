import { ActionIcon, Group, Tooltip } from "@mantine/core";
import { Download, Eye, Share2, Trash2 } from "lucide-react";
import { useState } from "react";
import { TtlPopover } from "@/components/TtlPopover/TtlPopover";

export interface FileActionsProps {
  isDirectory: boolean;
  canPreview: boolean;
  /** Display name of the file — used for accessible Download button label. */
  filename?: string;
  onDownload?: () => void;
  /** One-click copy with the default TTL. */
  onCopyUrl?: () => void;
  /** Copy with an explicit TTL chosen in the popover (right-click path). */
  onCopyUrlWithTtl?: (ttlSeconds: number) => void;
  onPreview?: () => void;
  onDelete: () => void;
  /** When true, Delete is rendered disabled with a config-aware tooltip. */
  disabled?: boolean;
  /** Server default presigned TTL (seconds) — preselected in the popover. */
  defaultTtl?: number;
  /** Configured max presigned TTL (seconds) — caps the popover options. */
  maxTtl?: number;
}

const DISABLED_DELETE_LABEL = "Deletion is disabled in the server config.";

export function FileActions({
  isDirectory,
  canPreview,
  filename,
  onDownload,
  onCopyUrl,
  onCopyUrlWithTtl,
  onPreview,
  onDelete,
  disabled = false,
  defaultTtl = 3600,
  maxTtl = 604800,
}: FileActionsProps) {
  const downloadLabel = filename ? `Download ${filename}` : "Download";
  const [ttlOpen, setTtlOpen] = useState(false);

  const canOverrideTtl = Boolean(onCopyUrlWithTtl);

  // Plain left-click always copies with the default TTL (one-click). The
  // per-link validity popover is opened with a right-click (context menu) —
  // a deliberate, discoverable affordance that keeps the common path one click.
  const handleShareClick = () => {
    onCopyUrl?.();
  };

  const handleShareContextMenu = (e: React.MouseEvent) => {
    if (!canOverrideTtl) return;
    e.preventDefault();
    setTtlOpen((o) => !o);
  };

  // Tooltip is placed INSIDE the shareIcon variable so that TtlPopover.target
  // receives the tooltip-wrapped ActionIcon directly. This avoids the
  // Tooltip-wrapping-Popover ref-forwarding conflict where both Mantine
  // components try to clone the same child and attach their own refs.
  // On the no-override branch the same tooltip-wrapped ActionIcon is rendered
  // directly, keeping visuals identical between the two paths.
  const shareLabel = canOverrideTtl
    ? "Copy link · right-click to set validity"
    : "Copy shareable link";
  const shareIcon = (
    <Tooltip label={shareLabel} withArrow>
      <ActionIcon
        variant="subtle"
        onClick={handleShareClick}
        onContextMenu={handleShareContextMenu}
        aria-label="Copy URL"
      >
        <Share2 size={16} />
      </ActionIcon>
    </Tooltip>
  );

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
        canOverrideTtl ? (
          <TtlPopover
            opened={ttlOpen}
            onClose={() => setTtlOpen(false)}
            defaultTtl={defaultTtl}
            maxTtl={maxTtl}
            onConfirm={(ttl) => onCopyUrlWithTtl?.(ttl)}
            target={shareIcon}
          />
        ) : (
          shareIcon
        )
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
