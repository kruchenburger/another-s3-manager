import { useState } from "react";
import { Button, Checkbox, Modal, Stack, Text, ThemeIcon } from "@mantine/core";
import { MousePointerClick, Sparkles } from "lucide-react";

const STORAGE_KEY = "upload:hintDismissed";

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

type UploadMode = "files" | "folder";

interface FolderUploadHintModalProps {
  /** Controlled open state. Parent owns the open/close transitions. */
  opened: boolean;
  /** Which entry point the user invoked. Controls the modal title and the
   *  primary CTA label, plus whether the "Don't show again" checkbox is
   *  pre-checked (folder picker is the more deliberate action — keep nagging;
   *  the plain upload button is high-frequency — pre-check the dismiss). */
  mode: UploadMode;
  /** Close the modal without proceeding (X button, click outside, Escape). */
  onClose: () => void;
  /** User chose the primary CTA — proceed with the picker matching `mode`. */
  onProceed: () => void;
}

/**
 * One-time onboarding modal that teaches drag-and-drop as the recommended
 * upload path. Shown the first time a user clicks "Upload" or "Upload folder";
 * a localStorage flag (`upload:hintDismissed=1`) suppresses it afterward.
 *
 * Why on plain Upload too: the React UI lost the vanilla's dedicated drop
 * zone visual, making drag-and-drop discoverable only by accident. Surfacing
 * the hint on first Upload click gives every new user a chance to learn the
 * better path, while the pre-checked "Don't show again" keeps the friction
 * to a single dismiss.
 *
 * The folder-mode call site keeps the modal as a deliberate "do you really
 * want the picker" step (matches the vanilla UI), so for that mode the
 * dismiss checkbox starts unchecked.
 */
export function FolderUploadHintModal({ opened, mode, onClose, onProceed }: FolderUploadHintModalProps) {
  // Pre-check the dismiss for plain-files mode (high-frequency action; we
  // don't want to nag); start unchecked for folder mode where the modal
  // doubles as the picker confirmation step.
  const initialDismiss = mode === "files";
  const [dontShowAgain, setDontShowAgain] = useState(initialDismiss);

  const handleProceed = () => {
    if (dontShowAgain) setDismissed();
    onProceed();
  };

  const handleClose = () => {
    if (dontShowAgain) setDismissed();
    onClose();
  };

  const title = mode === "folder" ? "Upload a folder" : "Upload files";
  const proceedLabel = mode === "folder" ? "Open folder picker" : "Choose files";
  const subtitle =
    mode === "folder"
      ? "Two ways to upload a folder, both preserve its structure:"
      : "You can also drag and drop — often faster:";

  return (
    <Modal
      opened={opened}
      onClose={handleClose}
      title={title}
      centered
      size="md"
      radius="lg"
    >
      <Stack gap="md">
        <Text size="sm" c="dimmed">
          {subtitle}
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
              {mode === "folder"
                ? "Drag a folder from your file manager onto this page. Works with multiple folders at once and skips the native picker dialog."
                : "Drag files from your file manager onto this page. Works with multiple files or whole folders at once."}
            </Text>
          </Stack>

          <Stack gap={4}>
            <Stack gap={4} style={{ flexDirection: "row", alignItems: "center" }}>
              <ThemeIcon variant="light" color="gray" size="md" radius="md">
                <MousePointerClick size={16} />
              </ThemeIcon>
              <Text fw={600}>
                {mode === "folder" ? "Browser folder picker" : "Browser file picker"}
              </Text>
            </Stack>
            <Text size="sm" c="dimmed" ml={44}>
              {mode === "folder"
                ? "Click below to open your browser's folder selection dialog."
                : "Click below to open your browser's file selection dialog."}
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
          <Button onClick={handleProceed}>{proceedLabel}</Button>
        </Stack>
      </Stack>
    </Modal>
  );
}
