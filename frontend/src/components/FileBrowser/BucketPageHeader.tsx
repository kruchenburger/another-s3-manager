import { Group, Stack, Text, Title } from "@mantine/core";
import { FileBreadcrumbs } from "./FileBreadcrumbs";
import { RoleBadge } from "./RoleBadge";

interface BucketPageHeaderProps {
  bucket: string;
  roleId: string;
  path: string;
  /** Loaded object count for this prefix — keeps ticking during Load more. */
  objectCount: number;
  /** S3 has more beyond the loaded set — render "N+" (honest counter). */
  truncated: boolean;
}

/** Page identity block (2026-05-20 critique §3.1): H2 bucket name + role
 * chip + count on row one, breadcrumbs as the smaller wayfinding row below.
 * Rendered in the PINNED chrome (inside .container, above the toolbar) —
 * the flex column absorbs its height, no scroll-container calc change. */
export function BucketPageHeader({
  bucket,
  roleId,
  path,
  objectCount,
  truncated,
}: BucketPageHeaderProps) {
  const countLabel = truncated
    ? `${objectCount}+ objects`
    : `${objectCount} object${objectCount === 1 ? "" : "s"}`;
  return (
    <Stack gap={2} mb="sm">
      <Group gap="sm" align="center" wrap="nowrap">
        <Title order={2} lineClamp={1}>
          {bucket}
        </Title>
        <RoleBadge roleId={roleId} />
        <Text size="sm" c="dimmed" span>
          ·
        </Text>
        <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap" }}>
          {countLabel}
        </Text>
      </Group>
      <FileBreadcrumbs bucket={bucket} roleId={roleId} path={path} />
    </Stack>
  );
}
