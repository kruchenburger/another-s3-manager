import { useEffect } from "react";
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
          <a
            onClick={onOpenTour}
            style={{ cursor: "pointer", textDecoration: "underline" }}
          >
            here
          </a>
          {" "}for a quick tour.
        </span>
      ),
      autoClose: 8000,
    });
    // Mark seen optimistically — don't show again on subsequent renders this session
    tourSeen.mutate();
  }, [me, onOpenTour, tourSeen]);

  return null;
}
