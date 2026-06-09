import { useEffect, useState, type RefObject } from "react";
import { Affix, ActionIcon, Transition } from "@mantine/core";
import { ArrowUp } from "lucide-react";

// Reveal the button once the user has scrolled ~half a viewport down the list.
const SCROLL_THRESHOLD = 400;

interface ScrollToTopButtonProps {
  /** The internal scroll container to observe and jump to top. */
  scrollRef: RefObject<HTMLDivElement | null>;
}

/**
 * Floating "scroll to top" affordance for the FileBrowser's internal scroll
 * container. Tracks `scrollRef.current.scrollTop` (the file list scrolls inside
 * its own bounded element, not the window) and jumps that element to the top.
 * The `data-scroll-to-top` marker drives the global.css :has() rule that lifts
 * bottom toasts above the button while it is on screen.
 */
export function ScrollToTopButton({ scrollRef }: ScrollToTopButtonProps) {
  const [scrolled, setScrolled] = useState(false);

  useEffect(() => {
    const el = scrollRef.current;
    if (!el) return;
    const onScroll = () => setScrolled(el.scrollTop > SCROLL_THRESHOLD);
    el.addEventListener("scroll", onScroll, { passive: true });
    onScroll(); // initialise in case the list is already scrolled
    return () => el.removeEventListener("scroll", onScroll);
  }, [scrollRef]);

  return (
    // right: 36 (not 20) clears the file-list's internal scrollbar. The list now
    // scrolls inside its own container whose scrollbar sits inset by the
    // AppShell.Main right padding (~16px) plus the scrollbar width (~15px); a
    // viewport-fixed button at right:20 landed on top of it. 36px restores the
    // same small gap the old window-scroll layout had.
    <Affix position={{ bottom: 20, right: 36 }}>
      <Transition transition="slide-up" mounted={scrolled}>
        {(styles) => (
          <ActionIcon
            style={styles}
            size="lg"
            radius="xl"
            variant="filled"
            aria-label="Scroll to top"
            data-scroll-to-top
            onClick={() =>
              scrollRef.current?.scrollTo({ top: 0, behavior: "smooth" })
            }
          >
            <ArrowUp size={20} />
          </ActionIcon>
        )}
      </Transition>
    </Affix>
  );
}
