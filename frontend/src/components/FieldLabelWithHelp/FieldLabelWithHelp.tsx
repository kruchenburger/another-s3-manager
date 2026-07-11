import { ActionIcon, Group, Popover, Text } from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { Info } from "lucide-react";
import type { MouseEvent, ReactNode } from "react";

export interface FieldLabelWithHelpProps {
  /** Field label text (rendered exactly like a plain `label` string would be). */
  label: string;
  /** Full explanation shown in the popover — click-to-open, not hover. */
  help: ReactNode;
}

/**
 * Drop-in replacement for a plain string `label` prop on Mantine form
 * inputs (`label={<FieldLabelWithHelp label="X" help="..." />}`). Renders the
 * label text plus a small info "i" chip that opens a Popover with the full
 * explanation on click — used to keep the persistent `description` under a
 * field down to one short line while still surfacing the full copy on demand.
 *
 * Icon sizing/opacity (`Info` at 14px, ~0.6 opacity) matches the existing
 * info-icon convention in RoleFormFields.tsx so it reads as native to the app.
 */
export function FieldLabelWithHelp({ label, help }: FieldLabelWithHelpProps) {
  const [opened, { toggle, close }] = useDisclosure(false);

  // The label text + chip render inside the input's own <label>. For Switch
  // fields that <label> also wraps the track (clicking anywhere in it toggles
  // the switch), so the chip's click must not bubble into that native
  // label-forwarding behavior — preventDefault + stopPropagation keeps the
  // click scoped to opening/closing the popover only.
  const handleClick = (event: MouseEvent<HTMLButtonElement>) => {
    event.preventDefault();
    event.stopPropagation();
    toggle();
  };

  return (
    <Group component="span" gap={6} wrap="nowrap">
      <span>{label}</span>
      <Popover
        width={300}
        position="top"
        withArrow
        shadow="md"
        opened={opened}
        onChange={close}
        withinPortal
      >
        <Popover.Target>
          <ActionIcon
            variant="subtle"
            color="gray"
            size="sm"
            radius="xl"
            onClick={handleClick}
            aria-label={`More about ${label}`}
          >
            <Info size={14} style={{ opacity: 0.6 }} />
          </ActionIcon>
        </Popover.Target>
        <Popover.Dropdown>
          <Text size="xs" c="dimmed">
            {help}
          </Text>
        </Popover.Dropdown>
      </Popover>
    </Group>
  );
}
