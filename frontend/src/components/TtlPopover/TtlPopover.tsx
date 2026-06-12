import { Button, Group, Popover, Select, Stack, Text } from "@mantine/core";
import { useEffect, useState } from "react";
import { ttlSelectDataUpTo, withConfiguredValue } from "@/utils/ttlPresets";

export interface TtlPopoverProps {
  /** Controlled open state. */
  opened: boolean;
  /** Called when the popover should close (outside click, Esc, after Copy). */
  onClose: () => void;
  /** Pre-selected TTL in seconds (the server default). */
  defaultTtl: number;
  /** Upper bound; presets above this are hidden. */
  maxTtl: number;
  /** Called with the chosen TTL (seconds) when the user clicks Copy. */
  onConfirm: (ttlSeconds: number) => void;
  /** The clickable element the popover anchors to. */
  target: React.ReactNode;
}

/**
 * "Valid for" popover for choosing a presigned-URL lifetime before copying.
 * Reused by single-file (Share2 icon, right-click) and bulk (split-button
 * chevron) Copy URL flows. The selection resets to `defaultTtl` each time the
 * popover (re)opens so it never carries a stale choice between files.
 */
export function TtlPopover({
  opened,
  onClose,
  defaultTtl,
  maxTtl,
  onConfirm,
  target,
}: TtlPopoverProps) {
  const [selected, setSelected] = useState<string>(String(defaultTtl));

  // Reset to the default whenever the popover opens or the default changes.
  useEffect(() => {
    if (opened) setSelected(String(defaultTtl));
  }, [opened, defaultTtl]);

  const data = withConfiguredValue(ttlSelectDataUpTo(maxTtl), defaultTtl);

  const handleCopy = () => {
    onConfirm(Number(selected));
    onClose();
  };

  return (
    <Popover
      opened={opened}
      onChange={(o) => !o && onClose()}
      position="bottom-end"
      withArrow
      shadow="md"
      trapFocus
    >
      <Popover.Target>{target}</Popover.Target>
      <Popover.Dropdown>
        <Stack gap="xs" w={200}>
          <Text size="sm" fw={600}>
            Share link validity
          </Text>
          <Select
            label="Valid for"
            data={data}
            value={selected}
            onChange={(v) => v && setSelected(v)}
            allowDeselect={false}
            // MUST stay false: a portaled dropdown renders OUTSIDE this Popover,
            // so clicking an option counts as an outside-click and closes the
            // Popover before the user can hit Copy. Rendering the option list
            // inside the Popover keeps the click "inside". The short option list
            // does not get clipped (Popover.Dropdown has no overflow:hidden).
            comboboxProps={{ withinPortal: false }}
            size="sm"
          />
          <Group justify="flex-end">
            <Button size="xs" onClick={handleCopy}>
              Copy
            </Button>
          </Group>
        </Stack>
      </Popover.Dropdown>
    </Popover>
  );
}
