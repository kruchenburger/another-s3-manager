import { Box, Button, Menu } from "@mantine/core";
import { ChevronDown, FileUp, FolderUp, Upload } from "lucide-react";
import classes from "./FileBrowser.module.css";

interface UploadSplitButtonProps {
  /** Open the file picker (multi-file input). */
  onUploadFiles: () => void;
  /** Open the folder picker (webkitdirectory input). */
  onUploadFolder: () => void;
}

/**
 * Consolidated upload control: a primary "Upload" (files) button with a chevron
 * menu exposing both upload modes. Replaces the two separate Upload / Upload
 * folder buttons in FileBrowserHeader (toolbar declutter). Both handlers already
 * route through FolderUploadHintModal on first use upstream — this is
 * presentation only.
 */
export function UploadSplitButton({
  onUploadFiles,
  onUploadFolder,
}: UploadSplitButtonProps) {
  return (
    <Button.Group>
      {/* Phones: icon-only (the text label hides) so the whole toolbar row —
          search icon, view toggle, Load split, Upload split — fits 360px.
          aria-label keeps the accessible name for tests/readers. */}
      <Button
        leftSection={<Upload size={14} />}
        onClick={onUploadFiles}
        size="sm"
        aria-label="Upload"
        className={classes.splitPrimary}
      >
        <Box component="span" visibleFrom="sm">
          Upload
        </Box>
      </Button>
      <Menu position="bottom-end" withinPortal>
        <Menu.Target>
          <Button px={8} size="sm" aria-label="More upload options">
            <ChevronDown size={14} />
          </Button>
        </Menu.Target>
        <Menu.Dropdown>
          <Menu.Item leftSection={<FileUp size={14} />} onClick={onUploadFiles}>
            Upload files
          </Menu.Item>
          <Menu.Item leftSection={<FolderUp size={14} />} onClick={onUploadFolder}>
            Upload folder
          </Menu.Item>
        </Menu.Dropdown>
      </Menu>
    </Button.Group>
  );
}
