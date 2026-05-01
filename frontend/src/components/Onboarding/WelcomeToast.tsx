import { useEffect } from "react";
import { Anchor } from "@mantine/core";
import { notifications } from "@mantine/notifications";
import { useMe } from "@/features/auth/hooks/useMe";
import { useTourSeen } from "@/features/auth/hooks/useTourSeen";

interface WelcomeToastProps {
  onOpenTour: () => void;
}

export function WelcomeToast({ onOpenTour }: WelcomeToastProps) {
  const { data: me } = useMe();
  const tourSeen = useTourSeen();

  useEffect(() => {
    if (!me || me.tour_seen_v1) return;
    notifications.show({
      title: "👋 Welcome!",
      message: (
        <span>
          Tap{" "}
          <Anchor component="button" type="button" onClick={onOpenTour}>
            here
          </Anchor>
          {" "}for a quick tour.
        </span>
      ),
      autoClose: 8000,
    });
    // Fire-and-forget: invalidates /api/me on success so subsequent renders
    // see tour_seen_v1=true and skip the early-exit branch above.
    // `tourSeen` is intentionally NOT in deps — the mutation result is a fresh
    // object every render, and including it would re-fire this effect 2-4
    // times before the cache invalidation lands.
    tourSeen.mutate();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [me, onOpenTour]);

  return null;
}
