import { useState } from "react";
import { Button, Checkbox, Modal, Stack, Text, ThemeIcon } from "@mantine/core";
import { MousePointerClick, Sparkles } from "lucide-react";

const STORAGE_KEY = "upload:folderHintDismissed";

/** Returns true when the user previously checked "don't show again". Reading is
 *  defensive — localStorage can be disabled (private mode, embedded WebViews),
 *  in which case we always show the modal (matches the safe default of more
 *  guidance, not less). */
export function hasDismissedFolderUploadHint(): boolean {
  if (typeof window === "undefined") return true; // SSR — never show
  try {
    return window.localStorage.getItem(STORAGE_KEY) === "1";
  } catch {
    return false;
  }
}

function setDismissed() {
  if (typeof window === "undefined") return;
  try {
    window.localStorage.setItem(STORAGE_KEY, "1");
  } catch {
    // localStorage unavailable — accept the cost of showing the modal again
    // next session rather than crashing.
  }
}

interface FolderUploadHintModalProps {
  /** Controlled open state. Parent owns the open/close transitions. */
  opened: boolean;
  /** Close the modal without proceeding (X button, click outside, Escape). */
  onClose: () => void;
  /** User chose "Open folder picker" — proceed with the browser dialog. */
  onProceed: () => void;
}

/**
 * One-time onboarding modal explaining the two ways to upload a folder.
 *
 * Vanilla UI showed a similar modal before triggering the browser's folder
 * picker. The React port skipped this step, which surprised users who knew
 * the vanilla behavior — and missed a chance to teach new users that
 * drag-and-drop preserves folder structure (it's the better path: no native
 * picker dialog, works with multiple folders at once, immediate feedback).
 *
 * A "Don't show again" checkbox stores a localStorage flag so power users
 * aren't nagged on every upload. The flag is per-browser (intentional —
 * if a user clears storage or moves to a new device, the hint comes back
 * as a refresher, not as a permanent annoyance).
 */
export function FolderUploadHintModal({ opened, onClose, onProceed }: FolderUploadHintModalProps) {
  const [dontShowAgain, setDontShowAgain] = useState(false);

  const handleProceed = () => {
    if (dontShowAgain) setDismissed();
    onProceed();
  };

  const handleClose = () => {
    if (dontShowAgain) setDismissed();
    onClose();
  };

  return (
    <Modal
      opened={opened}
      onClose={handleClose}
      title="Upload a folder"
      centered
      size="md"
      radius="lg"
    >
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          Two ways to upload a folder, both preserve its structure:
        </Text>

        <Stack gap="sm">
          <Stack gap={4}>
            <Stack gap={4} style={{ flexDirection: "row", alignItems: "center" }}>
              <ThemeIcon variant="light" color="amber" size="md" radius="md">
                <Sparkles size={16} />
              </ThemeIcon>
              <Text fw={600}>Drag and drop (recommended)</Text>
            </Stack>
            <Text size="sm" c="dimmed" ml={44}>
              Drag a folder from your file manager onto this page. Works with
              multiple folders at once and skips the native picker dialog.
            </Text>
          </Stack>

          <Stack gap={4}>
            <Stack gap={4} style={{ flexDirection: "row", alignItems: "center" }}>
              <ThemeIcon variant="light" color="gray" size="md" radius="md">
                <MousePointerClick size={16} />
              </ThemeIcon>
              <Text fw={600}>Browser folder picker</Text>
            </Stack>
            <Text size="sm" c="dimmed" ml={44}>
              Click below to open your browser's folder selection dialog.
            </Text>
          </Stack>
        </Stack>

        <Checkbox
          label="Don't show this again"
          checked={dontShowAgain}
          onChange={(e) => setDontShowAgain(e.currentTarget.checked)}
          size="sm"
        />

        <Stack gap={8} style={{ flexDirection: "row", justifyContent: "flex-end" }}>
          <Button variant="default" onClick={handleClose}>
            Cancel
          </Button>
          <Button onClick={handleProceed}>Open folder picker</Button>
        </Stack>
      </Stack>
    </Modal>
  );
}
