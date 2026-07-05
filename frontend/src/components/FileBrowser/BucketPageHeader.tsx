import { Group, Text, Title } from "@mantine/core";
import { useAnimatedNumber } from "@/hooks/useAnimatedNumber";
import { RoleBadge } from "./RoleBadge";

interface BucketPageHeaderProps {
  bucket: string;
  roleId: string;
  /** Loaded object count for this prefix — keeps ticking during Load more. */
  objectCount: number;
  /** S3 has more beyond the loaded set — render "N+" (honest counter). */
  truncated: boolean;
}

/** Page identity line (2026-05-20 critique §3.1): H2 bucket name + role
 * chip + count. Breadcrumbs stay in the toolbar row below (left of the
 * controls) — a dedicated breadcrumbs row left the toolbar's left half as
 * a dead "runway" (user smoke feedback). Rendered in the PINNED chrome
 * (inside .container) — the flex column absorbs its height, no
 * scroll-container calc change. */
export function BucketPageHeader({
  bucket,
  roleId,
  objectCount,
  truncated,
}: BucketPageHeaderProps) {
  // Count-up animation: Load more "runs" the counter 50 → 100 instead of
  // snapping (no animation on mount or under reduced motion). Suffix logic
  // uses the TARGET value so "1 object" / "N+ objects" never flickers.
  const animatedCount = useAnimatedNumber(objectCount);
  const countLabel = truncated
    ? `${animatedCount}+ objects`
    : `${animatedCount} object${objectCount === 1 ? "" : "s"}`;
  return (
    <Group gap="sm" align="center" wrap="nowrap" mb="xs">
      {/* minWidth: 0 lets the flex item actually shrink — without it
          min-width:auto blocks lineClamp and a long bucket name
          (jet-internal-...-pyroscope-data) pushes the badge + count out of
          view. Full name stays reachable via the native title tooltip. */}
      <Title order={2} lineClamp={1} title={bucket} miw={0}>
        {bucket}
      </Title>
      {/* Badge and count never shrink — identity chrome must stay visible
          no matter how long the bucket name is. */}
      <RoleBadge roleId={roleId} />
      <Text size="sm" c="dimmed" span style={{ flexShrink: 0 }}>
        ·
      </Text>
      <Text size="sm" c="dimmed" style={{ whiteSpace: "nowrap", flexShrink: 0 }}>
        {countLabel}
      </Text>
    </Group>
  );
}
