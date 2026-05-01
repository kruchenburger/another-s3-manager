import { useEffect } from "react";
import { Alert, Button, Card, PasswordInput, Stack, TextInput, Title } from "@mantine/core";
import { useForm } from "@mantine/form";
import { AlertCircle } from "lucide-react";
import { useNavigate, useLocation } from "react-router-dom";
import { useLogin } from "@/features/auth/hooks/useLogin";
import { useMe } from "@/features/auth/hooks/useMe";
import { BurgerLogo } from "@/components/BurgerLogo/BurgerLogo";
import { getErrorMessage } from "@/utils/apiError";
import classes from "./LoginPage.module.css";

interface LocationState {
  from?: string;
}

export function LoginPage() {
  const navigate = useNavigate();
  const location = useLocation();
  const { data: me } = useMe();
  const login = useLogin();

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
          <Title order={3}>Another S3 Manager</Title>
        </div>
        <form onSubmit={handleSubmit}>
          <Stack gap="md">
            {login.isError && (
              <Alert color="red" icon={<AlertCircle size={16} />}>
                {getErrorMessage(login.error)}
              </Alert>
            )}
            <TextInput label="Username" autoComplete="username" autoFocus {...form.getInputProps("username")} />
            <PasswordInput label="Password" autoComplete="current-password" {...form.getInputProps("password")} />
            <Button type="submit" fullWidth loading={login.isPending}>
              Login
            </Button>
          </Stack>
        </form>
      </Card>
    </div>
  );
}
