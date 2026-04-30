interface BurgerLogoProps {
  size?: number;
}

// Placeholder logo — slate bun + cheese slice silhouette.
// Replaced by full S3-themed BurgerLogo in backlog task 5.
export function BurgerLogo({ size = 32 }: BurgerLogoProps) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      viewBox="0 0 64 64"
      width={size}
      height={size}
      role="img"
      aria-label="Another S3 Manager logo"
    >
      <ellipse cx="32" cy="20" rx="26" ry="10" fill="#67748a" />
      <rect x="6" y="28" width="52" height="8" rx="2" fill="#ffc107" />
      <ellipse cx="32" cy="44" rx="26" ry="10" fill="#3b4658" />
    </svg>
  );
}
