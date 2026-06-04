import { Affix, ActionIcon, Transition } from "@mantine/core";
import { useWindowScroll } from "@mantine/hooks";
import { ArrowUp } from "lucide-react";

// Reveal the button once the user has scrolled ~half a viewport down — far
// enough that "back to top" is actually useful, close enough that it shows up
// before the user is deep into a long listing.
const SCROLL_THRESHOLD = 400;

/**
 * Floating "scroll to top" affordance for long file listings.
 *
 * The file browser scrolls the document (window-level), so visibility and the
 * jump-to-top action both ride on `useWindowScroll`. The Affix sits in the very
 * bottom-right corner; the global toast / upload-progress zone is lifted above
 * it (see `Notifications` in app/providers.tsx) so the two never overlap. A
 * slide-up Transition keeps the entrance/exit smooth, and `prefers-reduced-
 * motion` users get an instant jump because Mantine's scrollTo respects it.
 */
export function ScrollToTopButton() {
  const [scroll, scrollTo] = useWindowScroll();

  return (
    <Affix position={{ bottom: 20, right: 20 }}>
      <Transition transition="slide-up" mounted={scroll.y > SCROLL_THRESHOLD}>
        {(styles) => (
          <ActionIcon
            style={styles}
            size="lg"
            radius="xl"
            variant="filled"
            aria-label="Scroll to top"
            // Marker for the global.css :has() rule that lifts bottom toasts
            // above this button only while it is on screen.
            data-scroll-to-top
            onClick={() => scrollTo({ y: 0 })}
          >
            <ArrowUp size={20} />
          </ActionIcon>
        )}
      </Transition>
    </Affix>
  );
}
