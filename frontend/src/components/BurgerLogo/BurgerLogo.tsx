import { useRef } from "react";
import { Center } from "@mantine/core";
import { useGSAP } from "@gsap/react";
import gsap from "gsap";
import classes from "./BurgerLogo.module.css";

export type BurgerLogoMode = "static" | "loader" | "idle" | "error" | "notfound" | "crash";

interface BurgerLogoProps {
  size?: number;
  mode?: BurgerLogoMode;
  /** Signal that loading is complete — `loader` mode finishes current cycle with a bounce */
  ready?: boolean;
  /** Called after the loader finish-bounce completes */
  onComplete?: () => void;
  /** Expose a replay trigger for `crash` mode (set via ref callback) */
  onReplayRef?: React.MutableRefObject<(() => void) | null>;
}

const prefersReducedMotion =
  typeof window !== "undefined" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * kruchenburger-family BurgerLogo for another-s3-manager.
 * Files-as-filling concept: slate bun + 3 amber file plates + slate bun + seeds.
 *
 * Modes:
 *  - static   — no animation at all (header icon, repeated renders)
 *  - loader   — assemble → if ready: bounce-complete; else: disassemble + loop
 *  - idle     — one-time assemble + settle (no looping yoyo)
 *  - error    — assemble → shake (used by 403 ForbiddenPage)
 *  - notfound — assemble → tilt 12° + drop 8px ("oops" effect, used by 404)
 *  - crash    — assemble → random scatter (3 variants) → gentle floating, +Replay (used by 500)
 *
 * GSAP timeline structure ported from vpn/webapp/src/components/BurgerLogo.tsx.
 * SVG geometry is new (file plates instead of patty/lettuce).
 */
export function BurgerLogo({
  size = 32,
  mode = "idle",
  ready,
  onComplete,
  onReplayRef,
}: BurgerLogoProps) {
  const containerRef = useRef<HTMLDivElement>(null);
  const readyRef = useRef(false);
  readyRef.current = ready ?? false;
  const onCompleteRef = useRef(onComplete);
  onCompleteRef.current = onComplete;

  useGSAP(
    () => {
      // static mode: no animation, ever. Used in repeated places (header icon)
      // where animation would be distracting.
      if (mode === "static") return;

      if (prefersReducedMotion) {
        if (mode === "loader") onCompleteRef.current?.();
        return;
      }

      const container = containerRef.current;
      if (!container) return;

      // Assembly order: bottom bun → file plates (3) → top bun + seeds
      const bottomBun = container.querySelector('[data-layer="bottom-bun"]');
      const file1 = container.querySelector('[data-layer="file-1"]');
      const file2 = container.querySelector('[data-layer="file-2"]');
      const file3 = container.querySelector('[data-layer="file-3"]');
      const topBun = container.querySelector('[data-layer="top-bun"]');
      const seeds = container.querySelectorAll('[data-layer="seed"]');

      const layers = [bottomBun, file1, file2, file3, topBun, ...seeds].filter(
        Boolean,
      );

      if (mode === "loader") {
        const buildCycle = () => {
          const tl = gsap.timeline();
          tl.set(layers, { y: -60, opacity: 0 });
          tl.to(layers, {
            y: 0,
            opacity: 1,
            duration: 0.3,
            stagger: 0.08,
            ease: "back.out(1.7)",
          });
          tl.call(() => {
            if (readyRef.current) {
              gsap.to(container, {
                keyframes: [
                  { scale: 1.15, duration: 0.12, ease: "power2.out" },
                  { scale: 1, duration: 0.15, ease: "bounce.out" },
                ],
                onComplete: () => onCompleteRef.current?.(),
              });
            } else {
              const tl2 = gsap.timeline();
              tl2.to(layers, {
                y: -60,
                opacity: 0,
                duration: 0.2,
                stagger: 0.04,
                ease: "power2.in",
                delay: 0.3,
              });
              tl2.call(buildCycle, undefined, "+=0.15");
            }
          });
        };
        buildCycle();
        return;
      }

      if (mode === "idle") {
        // One-time assemble, then settle. No looping yoyo — the breathing animation
        // turned out to be distracting on a hero element rather than charming.
        const tl = gsap.timeline();
        tl.set(layers, { y: -60, opacity: 0 });
        tl.to(layers, {
          y: 0,
          opacity: 1,
          duration: 0.4,
          stagger: 0.12,
          ease: "back.out(1.7)",
        });
        return;
      }

      if (mode === "error") {
        const tl = gsap.timeline();
        tl.set(layers, { y: -60, opacity: 0 });
        tl.to(layers, {
          y: 0,
          opacity: 1,
          duration: 0.35,
          stagger: 0.1,
          ease: "back.out(1.7)",
        });
        tl.to(container, {
          keyframes: [
            { x: -8, duration: 0.07 },
            { x: 8, duration: 0.07 },
            { x: -6, duration: 0.07 },
            { x: 6, duration: 0.07 },
            { x: -3, duration: 0.07 },
            { x: 3, duration: 0.07 },
            { x: 0, duration: 0.07 },
          ],
          delay: 0.2,
        });
        return;
      }

      if (mode === "notfound") {
        const tl = gsap.timeline();
        tl.set(layers, { y: -60, opacity: 0 });
        tl.to(layers, {
          y: 0,
          opacity: 1,
          duration: 0.35,
          stagger: 0.1,
          ease: "back.out(1.7)",
        });
        tl.to(container, {
          rotation: 12,
          y: 8,
          duration: 0.6,
          ease: "power2.inOut",
          delay: 0.2,
        });
        return;
      }

      if (mode === "crash") {
        const topGroupEl = container.querySelector('[data-layer="top-group"]');
        const scatterTargets = [bottomBun, file1, file2, file3, topGroupEl].filter(Boolean);

        let tl: gsap.core.Timeline;

        const scatterVariants = [
          // 1. Top bun flies left, bottom bun drops right, files spread
          () => {
            tl.to(bottomBun, { y: 18, x: 4, rotation: 14, duration: 0.35, ease: "back.out(2)" }, "+=0.4");
            tl.to(file1, { x: -8, y: 6, rotation: -8, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file2, { x: 10, y: -2, rotation: 12, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file3, { x: -4, y: 10, rotation: 6, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(topGroupEl, { x: -3, y: -22, rotation: -15, svgOrigin: "28 20", duration: 0.35, ease: "back.out(2)" }, "<");
          },
          // 2. Everything tilts right, top bun flies up-right
          () => {
            tl.to(bottomBun, { y: 14, x: -6, rotation: -10, duration: 0.35, ease: "back.out(2)" }, "+=0.4");
            tl.to(file1, { x: 10, y: 4, rotation: 12, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file2, { x: -7, y: -8, rotation: -6, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file3, { x: 8, y: 12, rotation: 8, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(topGroupEl, { x: 6, y: -20, rotation: 18, svgOrigin: "28 20", duration: 0.35, ease: "back.out(2)" }, "<");
          },
          // 3. Symmetric explosion
          () => {
            tl.to(bottomBun, { y: 20, rotation: 5, duration: 0.35, ease: "back.out(2)" }, "+=0.4");
            tl.to(file1, { x: -12, y: 2, rotation: -10, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file2, { x: 12, y: -2, rotation: 10, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(file3, { x: 0, y: 14, rotation: 0, duration: 0.35, ease: "back.out(2)" }, "<");
            tl.to(topGroupEl, { y: -24, rotation: -3, svgOrigin: "28 20", duration: 0.35, ease: "back.out(2)" }, "<");
          },
        ];

        const runCrash = () => {
          gsap.killTweensOf([...layers, ...scatterTargets, container]);
          // Include container in clearProps so any leftover transform from a
          // prior idle/loader mode (e.g. scale 1.05 from breathing) is wiped.
          gsap.set([...layers, ...scatterTargets, container], { clearProps: "all" });

          tl = gsap.timeline();
          tl.set(layers, { y: -60, opacity: 0 });
          tl.to(layers, {
            y: 0,
            opacity: 1,
            duration: 0.3,
            stagger: 0.08,
            ease: "back.out(1.7)",
          });
          scatterVariants[Math.floor(Math.random() * scatterVariants.length)]();
          // Gentle floating
          tl.to(bottomBun, { y: "+=3", duration: 1.5, yoyo: true, repeat: -1, ease: "sine.inOut" });
          tl.to(file1, { y: "+=3", duration: 1.7, yoyo: true, repeat: -1, ease: "sine.inOut" }, "<0.1");
          tl.to(file2, { y: "+=4", duration: 1.8, yoyo: true, repeat: -1, ease: "sine.inOut" }, "<0.1");
          tl.to(file3, { y: "+=3.5", duration: 1.6, yoyo: true, repeat: -1, ease: "sine.inOut" }, "<0.1");
          tl.to(topGroupEl, { y: "+=3", duration: 1.7, yoyo: true, repeat: -1, ease: "sine.inOut" }, "<0.1");
        };

        runCrash();

        if (onReplayRef) onReplayRef.current = runCrash;
        return;
      }
    },
    { scope: containerRef, dependencies: [mode] },
  );

  return (
    <Center
      ref={containerRef}
      className={classes.container}
      display="inline-flex"
      // Numeric size has no Mantine prop equivalent (w/h take spacing tokens or strings),
      // so width/height stay inline. Layout (display/align/justify) goes through Center.
      style={{ width: size, height: size }}
    >
      <svg
        width={size}
        height={size}
        viewBox="0 0 56 56"
        fill="none"
        overflow="visible"
        xmlns="http://www.w3.org/2000/svg"
        role="img"
        aria-label="Another S3 Manager"
      >
        <g data-layer="top-group">
          {/* Top bun — slate dome */}
          <path
            data-layer="top-bun"
            d="M8 24c0-9.9 8.1-18 20-18s20 8.1 20 18H8z"
            fill="url(#bun-gradient)"
          />
          {/* Sesame seeds */}
          <circle data-layer="seed" cx="18" cy="20" r="1.2" fill="rgba(255,255,255,0.5)" />
          <circle data-layer="seed" cx="28" cy="17" r="1.2" fill="rgba(255,255,255,0.5)" />
          <circle data-layer="seed" cx="36" cy="20" r="1.2" fill="rgba(255,255,255,0.5)" />
        </g>

        {/* File plates — 3 layers in amber shades, sized to look like a stack of documents */}
        <rect data-layer="file-1" x="6" y="26" width="44" height="4" rx="1" fill="#ffd54f" />
        <rect data-layer="file-2" x="7" y="31" width="42" height="4" rx="1" fill="#ffc107" />
        <rect data-layer="file-3" x="6" y="36" width="44" height="4" rx="1" fill="#ffa000" />

        {/* Bottom bun — slate base */}
        <path
          data-layer="bottom-bun"
          d="M6 42h44v4a3 3 0 01-3 3H9a3 3 0 01-3-3v-4z"
          fill="url(#bun-gradient)"
        />
        <defs>
          <linearGradient id="bun-gradient" x1="28" y1="6" x2="28" y2="49" gradientUnits="userSpaceOnUse">
            <stop stopColor="#67748a" />
            <stop offset="1" stopColor="#3b4658" />
          </linearGradient>
        </defs>
      </svg>
    </Center>
  );
}
