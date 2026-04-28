import { MantineProvider } from "@mantine/core";
import "@mantine/core/styles.css";
import { theme } from "./theme";

export function App() {
  return (
    <MantineProvider theme={theme} defaultColorScheme="auto">
      <div>Another S3 Manager — React frontend (WIP)</div>
    </MantineProvider>
  );
}
