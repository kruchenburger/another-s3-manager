import { useEffect, useState } from "react";
import { Button, Group, Text, Title } from "@mantine/core";
import classes from "./SpotlightTour.module.css";

interface Step {
  selector: string;
  title: string;
  description: string;
}

const STEPS: Step[] = [
  {
    selector: "[data-tour='sidebar']",
    title: "Your roles & buckets",
    description: "All the storage roles you can access live here. Click a role to expand its buckets.",
  },
  {
    selector: "[data-tour='collapse-btn']",
    title: "More space",
    description: "Click here to collapse the sidebar to icons only.",
  },
  {
    selector: "[data-tour='file-list']",
    title: "File actions",
    description: "Hover any file to download, copy its link, preview it, or delete it.",
  },
  {
    selector: "[data-tour='upload-btn']",
    title: "Upload",
    description: "Drop files anywhere on the page to upload, or click here to pick.",
  },
];

interface SpotlightTourProps {
  open: boolean;
  onClose: () => void;
}

export function SpotlightTour({ open, onClose }: SpotlightTourProps) {
  const [stepIndex, setStepIndex] = useState(0);
  const [rect, setRect] = useState<DOMRect | null>(null);

  useEffect(() => {
    if (!open) {
      setStepIndex(0);
      return;
    }
    const step = STEPS[stepIndex];
    const target = document.querySelector(step.selector) as HTMLElement | null;
    if (target) {
      target.scrollIntoView({ block: "center", behavior: "smooth" });
      // Recompute on next frame after scroll
      requestAnimationFrame(() => setRect(target.getBoundingClientRect()));
    } else {
      // If target doesn't exist (e.g. file-list selector but no files), skip
      setRect(null);
    }
  }, [open, stepIndex]);

  if (!open) return null;

  const step = STEPS[stepIndex];
  const isLast = stepIndex === STEPS.length - 1;

  // Position popover below the target with 16px gap, fallback to center if no rect
  const popoverStyle = rect
    ? {
        top: rect.bottom + 16,
        left: Math.max(16, Math.min(rect.left, window.innerWidth - 336)),
      }
    : {
        top: "50%",
        left: "50%",
        transform: "translate(-50%, -50%)",
      };

  return (
    <>
      <div className={classes.overlay} onClick={onClose} />
      {rect && (
        <div
          className={classes.spotlight}
          style={{
            top: rect.top - 4,
            left: rect.left - 4,
            width: rect.width + 8,
            height: rect.height + 8,
          }}
        />
      )}
      <div className={classes.popover} style={popoverStyle}>
        <Title order={5} mb="xs">
          {step.title}
        </Title>
        <Text size="sm" mb="md">
          {step.description}
        </Text>
        <Group justify="space-between">
          <Button variant="subtle" size="xs" onClick={onClose}>
            Skip
          </Button>
          <Group gap="xs">
            <Text size="xs" c="dimmed">
              {stepIndex + 1} / {STEPS.length}
            </Text>
            <Button
              size="xs"
              onClick={() => {
                if (isLast) {
                  onClose();
                } else {
                  setStepIndex((i) => i + 1);
                }
              }}
            >
              {isLast ? "Got it!" : "Next"}
            </Button>
          </Group>
        </Group>
      </div>
    </>
  );
}
