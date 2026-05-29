import { Center } from "@mantine/core";
import { useGSAP } from "@gsap/react";
import { useRef } from "react";
import {
  prepareCubes,
  TIMELINE_BUILDERS,
  type AnimationMode,
} from "./animations";
import classes from "./CubeLogo.module.css";

export type CubeLogoMode = "static" | AnimationMode;
// Static is rendered without GSAP. AnimationMode covers idle / error /
// notfound / crash — the `loader` GSAP timeline used to live here too
// but the loading state across the app is now served by Mantine
// <Loader /> (see DelayedLoader) because the CSS halo glow stalled
// under heavy file-table render and Firefox flagged the page as
// "slowing down".

interface CubeLogoProps {
  size?: number;
  mode?: CubeLogoMode;
}

const prefersReducedMotion =
  typeof window !== "undefined" &&
  window.matchMedia("(prefers-reduced-motion: reduce)").matches;

/**
 * CubeLogo — three isometric cubes in pyramid composition (1 top,
 * 2 bottom), Muted Slate-Blue palette. Used as the brand mark on
 * login, error pages, AuthGuard fallback, and the sidebar. For
 * loading states, prefer DelayedLoader (Mantine spinner).
 */
export function CubeLogo({ size = 32, mode = "static" }: CubeLogoProps) {
  const svgRef = useRef<SVGSVGElement>(null);

  useGSAP(
    () => {
      if (mode === "static" || prefersReducedMotion) return;
      if (!svgRef.current) return;
      const svg = svgRef.current;
      const cubes = {
        bottomLeft: svg.querySelector<SVGGElement>(
          '[data-layer="cube-bottom-left"]',
        )!,
        bottomRight: svg.querySelector<SVGGElement>(
          '[data-layer="cube-bottom-right"]',
        )!,
        top: svg.querySelector<SVGGElement>('[data-layer="cube-top"]')!,
      };
      prepareCubes(cubes);
      TIMELINE_BUILDERS[mode](cubes, svg);
      // useGSAP auto-kills any timelines created in scope on cleanup.
    },
    { scope: svgRef, dependencies: [mode] },
  );

  return (
    <Center display="inline-flex" style={{ width: size, height: size }}>
      <svg
        ref={svgRef}
        width={size}
        height={size}
        viewBox="0 0 56 56"
        role="img"
        aria-label="Another S3 Manager"
        xmlns="http://www.w3.org/2000/svg"
      >
        <defs>
          <linearGradient id="csm-f" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#6587B0" />
            <stop offset="1" stopColor="#52739C" />
          </linearGradient>
          <linearGradient id="csm-t" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#B3C9E4" />
            <stop offset="1" stopColor="#94B0D2" />
          </linearGradient>
          <linearGradient id="csm-s" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stopColor="#33506F" />
            <stop offset="1" stopColor="#243A55" />
          </linearGradient>
        </defs>
        {/* Each cube is wrapped in an inner <g class={classes.cube}> so
            GSAP timelines can apply scale/filter to the polygon group
            without overwriting the outer translate() that positions the
            cube in the pyramid. */}
        <g transform="translate(8 25)" data-layer="cube-bottom-left">
          <g className={classes.cube}>
            <polygon
              points="10,0 20,5 20,15 10,20 0,15 0,5"
              fill="url(#csm-f)"
            />
            <polygon points="10,0 20,5 10,10 0,5" fill="url(#csm-t)" />
            <polygon points="10,10 20,5 20,15 10,20" fill="url(#csm-s)" />
          </g>
        </g>
        <g transform="translate(28 25)" data-layer="cube-bottom-right">
          <g className={classes.cube}>
            <polygon
              points="10,0 20,5 20,15 10,20 0,15 0,5"
              fill="url(#csm-f)"
            />
            <polygon points="10,0 20,5 10,10 0,5" fill="url(#csm-t)" />
            <polygon points="10,10 20,5 20,15 10,20" fill="url(#csm-s)" />
          </g>
        </g>
        <g transform="translate(18 10)" data-layer="cube-top">
          <g className={classes.cube}>
            <polygon
              points="10,0 20,5 20,15 10,20 0,15 0,5"
              fill="url(#csm-f)"
            />
            <polygon points="10,0 20,5 10,10 0,5" fill="url(#csm-t)" />
            <polygon points="10,10 20,5 20,15 10,20" fill="url(#csm-s)" />
          </g>
        </g>
        {/* Ghost layer — dashed outline + "?" glyph that pulse in during
            the `notfound` animation while the apex cube fades out. Kept
            in a SEPARATE <g> next to cube-top (not inside it) because
            GSAP animates cube-top's opacity to 0 during the notfound
            timeline, which would also hide these descendants. The ghost
            elements get their own opacity tweens via the animation
            builder's container.querySelector lookups. */}
        <g transform="translate(18 10)" data-layer="cube-top-ghost">
          <polygon
            data-ghost-slot=""
            points="10,0 20,5 20,15 10,20 0,15 0,5"
            fill="none"
            stroke="#5E7FA8"
            strokeWidth="0.6"
            strokeDasharray="1.2 1.2"
            strokeLinejoin="round"
            opacity="0"
          />
          <text
            data-ghost-q=""
            x="10"
            y="13"
            textAnchor="middle"
            fill="#5E7FA8"
            fontSize="9"
            fontWeight="700"
            fontFamily="ui-monospace, 'JetBrains Mono', monospace"
            opacity="0"
          >
            ?
          </text>
        </g>
      </svg>
    </Center>
  );
}
