import { Group, Progress, Text } from "@mantine/core";

export interface UploadProgressItem {
  name: string;
  status: "pending" | "uploading" | "done" | "error";
  error?: string;
}

interface UploadProgressProps {
  items: UploadProgressItem[];
}

export function UploadProgress({ items }: UploadProgressProps) {
  const total = items.length;
  const done = items.filter((i) => i.status === "done").length;
  const errors = items.filter((i) => i.status === "error").length;
  const percent = total === 0 ? 0 : Math.round((done / total) * 100);

  return (
    <div>
      <Group justify="space-between" mb={4}>
        <Text size="sm" fw={500}>
          Uploading {total} {total === 1 ? "file" : "files"}
        </Text>
        <Text size="sm" c="dimmed">
          {done}/{total} {errors > 0 && `(${errors} failed)`}
        </Text>
      </Group>
      <Progress value={percent} color={errors > 0 ? "yellow" : "amber"} />
    </div>
  );
}
