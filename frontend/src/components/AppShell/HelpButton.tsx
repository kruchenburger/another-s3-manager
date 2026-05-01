import { ActionIcon } from "@mantine/core";
import { HelpCircle } from "lucide-react";

interface HelpButtonProps {
  onClick: () => void;
}

export function HelpButton({ onClick }: HelpButtonProps) {
  return (
    <ActionIcon variant="default" size="lg" onClick={onClick} aria-label="Open help" title="Help">
      <HelpCircle size={18} />
    </ActionIcon>
  );
}
