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
import { AlertCircle } from "lucide-react";
import { useNavigate, useLocation } from "react-router-dom";
import { useLogin } from "@/features/auth/hooks/useLogin";
import { useMe } from "@/features/auth/hooks/useMe";
import { useAppInfo } from "@/hooks/useAppInfo";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { GITHUB_URL } from "@/constants/links";
import { getErrorMessage } from "@/utils/apiError";
import classes from "./LoginPage.module.css";

interface LocationState {
  from?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { data: me } = useMe();
  const { data: appInfo } = useAppInfo();
  const login = useLogin();

  const appName = appInfo?.app_name ?? "Another S3 Manager";
  const appVersion = appInfo?.app_version;
  // Hide the footer when the server hasn't reported a version yet or when
  // running locally (`dev`) — version chrome on a dev build is just noise.
  const showFooter = !!appVersion && appVersion !== "dev";

  const form = useForm({
    initialValues: { username: "", password: "" },
    validate: {
      username: (v) => (v.trim().length === 0 ? "Username is required" : null),
      password: (v) => (v.length === 0 ? "Password is required" : null),
    },
  });

  // If already authenticated (e.g. user navigated back to /login), bounce to home.
  useEffect(() => {
    if (me) {
      const from = (location.state as LocationState | null)?.from ?? "/";
      navigate(from, { replace: true });
    }
  }, [me, location.state, navigate]);

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
          <BurgerLogo size={96} mode="idle" />
          <Title order={3}>{appName}</Title>
          <Text size="sm" c="dimmed" className={classes.tagline}>
            Lightweight S3 file manager
          </Text>
        </div>
        <form onSubmit={handleSubmit}>
          <Stack gap="md">
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
            <Button type="submit" fullWidth loading={login.isPending}>
              Login
            </Button>
          </Stack>
        </form>
      </Card>
      {showFooter && (
        <Group justify="center" gap="xs" mt="md" className={classes.footer}>
          <Text size="xs" c="dimmed">
            v{appVersion}
          </Text>
          <Text size="xs" c="dimmed">
            ·
          </Text>
          <Anchor
            href={GITHUB_URL}
            target="_blank"
            rel="noopener noreferrer"
            size="xs"
            c="dimmed"
          >
            Source on GitHub
          </Anchor>
        </Group>
      )}
    </div>
  );
}
