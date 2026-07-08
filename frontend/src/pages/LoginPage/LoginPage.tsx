import { useEffect } from "react";
import {
  Alert,
  Anchor,
  Button,
  Card,
  Group,
  PasswordInput,
  Stack,
  Text,
  TextInput,
  Title,
} from "@mantine/core";
import { useForm } from "@mantine/form";
import { AlertCircle, Github } from "lucide-react";
import { useNavigate, useLocation } from "react-router-dom";
import { useLogin } from "@/features/auth/hooks/useLogin";
import { useMe } from "@/features/auth/hooks/useMe";
import { useAppInfo } from "@/hooks/useAppInfo";
import { CubeLogo } from "@/components/CubeLogo/CubeLogo";
import { GITHUB_URL } from "@/constants/links";
import { getErrorMessage } from "@/utils/apiError";
import classes from "./LoginPage.module.css";

interface LocationState {
  from?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { data: me, isSuccess: meIsValid } = useMe();
  const { data: appInfo } = useAppInfo();
  const login = useLogin();

  const appName = appInfo?.app_name ?? "Another S3 Manager";

  const form = useForm({
    initialValues: { username: "", password: "" },
    validate: {
      username: (v) => (v.trim().length === 0 ? "Username is required" : null),
      password: (v) => (v.length === 0 ? "Password is required" : null),
    },
  });

  // If already authenticated (e.g. user navigated back to /login), bounce to home.
  //
  // Gate on isSuccess, NOT just `me` being truthy: when a session expires, the
  // /api/me query keeps its last-good `data` while a background refetch (fired by
  // refetchOnWindowFocus when the user returns to the tab) errors with 401. At
  // that moment AuthGuard sees the error and redirects here, but `me` is still
  // the stale object — bouncing on `me` alone would send the user straight back
  // to the app, which redirects here again: a tight redirect loop that flickers
  // the address bar and freezes the page. isSuccess is false while the query is
  // in that errored state, so we stay on /login and let the user re-auth.
  useEffect(() => {
    if (me && meIsValid) {
      const from = (location.state as LocationState | null)?.from ?? "/";
      navigate(from, { replace: true });
    }
  }, [me, meIsValid, location.state, navigate]);

  const handleSubmit = form.onSubmit((values) => {
    login.mutate(values, {
      onSuccess: () => {
        const from = (location.state as LocationState | null)?.from ?? "/";
        navigate(from, { replace: true });
      },
    });
  });

  return (
    <div className={classes.shell}>
      <Card className={classes.card} padding="xl">
        <div className={classes.brand}>
          <CubeLogo size={96} mode="static" />
          <Title order={2}>{appName}</Title>
        </div>
        <form onSubmit={handleSubmit}>
          <Stack gap="sm">
            {login.isError && (
              <Alert color="red" icon={<AlertCircle size={16} />}>
                {getErrorMessage(login.error)}
              </Alert>
            )}
            <TextInput
              label="Username"
              autoComplete="username"
              autoFocus
              {...form.getInputProps("username")}
            />
            <PasswordInput
              label="Password"
              autoComplete="current-password"
              {...form.getInputProps("password")}
            />
            {/* Subtle variant matches the mockup — the login card already
                has plenty of weight from the brand stack at the top, so a
                solid-blue CTA fights for attention. `subtle` reads as the
                primary affordance without becoming the focal point.
                Label kept as "Login" so existing e2e fixtures still
                match the button via getByRole(name: "Login"). */}
            <Button
              type="submit"
              fullWidth
              loading={login.isPending}
              variant="subtle"
              mt="xs"
            >
              Login
            </Button>
          </Stack>
        </form>
      </Card>
      <Group justify="center" gap="xs" mt="md" className={classes.footer}>
        {appInfo?.app_version && (
          <>
            <Text size="xs" c="dimmed" ff="monospace">
              v{appInfo.app_version}
            </Text>
            <Text size="xs" c="dimmed">
              ·
            </Text>
          </>
        )}
        <Anchor
          href={GITHUB_URL}
          target="_blank"
          rel="noopener noreferrer"
          size="xs"
          c="dimmed"
        >
          <Group gap={4} wrap="nowrap" align="center">
            {/* Inline Github mark next to the link so the footer reads as
                a clickable affordance instead of bare grey text. Matches
                the mockup in design/footer-mockup.png. Sized 12 to align
                with the xs-size text x-height; aria-hidden because the
                link label already says "GitHub". */}
            <Github size={12} aria-hidden="true" />
            <span>Source on GitHub</span>
          </Group>
        </Anchor>
      </Group>
    </div>
  );
}
