import { useEffect, useState } from "react";
import { Center, Stack, Text } from "@mantine/core";
import { Navigate, Outlet, useLocation } from "react-router-dom";
import { useMe } from "@/features/auth/hooks/useMe";
import { ApiError } from "@/utils/apiError";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";

// Gates protected routes. Behavior:
//   - loading → BurgerLogo loader animation (assembles, loops while waiting,
//     bounces when ready)
//   - 401     → redirect to /login
//   - other error → bubble to ErrorBoundary
//   - success → render children via <Outlet />
export function AuthGuard() {
  const location = useLocation();
  const { data, isLoading, error } = useMe();
  // The `loader` BurgerLogo mode keeps cycling until `ready=true`. We delay
  // the actual render until the loader bounce-completes — feels intentional
  // instead of jarring.
  const [loaderDone, setLoaderDone] = useState(false);
  const ready = !isLoading;

  // If auth resolves so fast the loader never even starts a cycle (cached me),
  // skip the bounce and render immediately.
  useEffect(() => {
    if (!isLoading && !loaderDone) {
      // Give GSAP one paint to attach + run a quick cycle. If still nothing
      // after 600ms, force-render anyway.
      const timer = setTimeout(() => setLoaderDone(true), 600);
      return () => clearTimeout(timer);
    }
  }, [isLoading, loaderDone]);

  if (isLoading || !loaderDone) {
    return (
      <Center h="100vh">
        <Stack align="center" gap="md">
          <BurgerLogo
            size={80}
            mode="loader"
            ready={ready}
            onComplete={() => setLoaderDone(true)}
          />
          <Text size="sm" c="dimmed">
            Loading…
          </Text>
        </Stack>
      </Center>
    );
  }

  if (error) {
    if (error instanceof ApiError && error.isAuthError()) {
      return <Navigate to="/login" replace state={{ from: location.pathname }} />;
    }
    throw error;
  }

  if (!data) {
    return <Navigate to="/login" replace />;
  }

  return <Outlet />;
}
