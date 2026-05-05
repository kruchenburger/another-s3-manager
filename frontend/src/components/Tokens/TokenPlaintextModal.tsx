import {
  ActionIcon,
  Alert,
  Box,
  Button,
  Code,
  Collapse,
  Group,
  Modal,
  Stack,
  Text,
} from "@mantine/core";
import { useDisclosure } from "@mantine/hooks";
import { notifications } from "@mantine/notifications";
import { ChevronDown, ChevronRight, Copy } from "lucide-react";
import { useState } from "react";

interface TokenPlaintextModalProps {
  opened: boolean;
  onClose: () => void;
  plaintext: string;
  noteForAdmin?: string;
}

export function TokenPlaintextModal({ opened, onClose, plaintext, noteForAdmin }: TokenPlaintextModalProps) {
  const [snippetOpen, snippet] = useDisclosure(false);
  const [copied, setCopied] = useState(false);

  // Note: url ends with a trailing slash (`/mcp/`) — Starlette's Mount route
  // 307-redirects /mcp -> /mcp/ and not all MCP clients follow that redirect
  // cleanly. Always advertise the canonical path. type: "http" is the
  // Streamable HTTP transport hint required by VS Code and other clients.
  const mcpSnippet = JSON.stringify(
    {
      mcpServers: {
        "another-s3-manager": {
          type: "http",
          url: `${typeof window !== "undefined" ? window.location.origin : ""}/mcp/`,
          headers: { Authorization: `Bearer ${plaintext}` },
        },
      },
    },
    null,
    2,
  );

  async function copy(text: string) {
    try {
      await navigator.clipboard.writeText(text);
      setCopied(true);
      notifications.show({ title: "Copied", message: "Token copied to clipboard", color: "green" });
      setTimeout(() => setCopied(false), 2000);
    } catch {
      notifications.show({ title: "Copy failed", message: "Use manual copy", color: "red" });
    }
  }

  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="Token created — copy it now"
      centered
      size="lg"
      radius="lg"
      closeOnEscape={false}
      closeOnClickOutside={false}
      withCloseButton={false}
    >
      <Stack gap="md">
        <Alert color="red" title="This token will not be shown again">
          Save it in your secret manager NOW. If you lose it, revoke and create a new one.
          {noteForAdmin && (
            <Text size="sm" mt="xs">
              {noteForAdmin}
            </Text>
          )}
        </Alert>
        <Box pos="relative">
          <Code block pr={40} style={{ wordBreak: "break-all" }}>
            {plaintext}
          </Code>
          <ActionIcon
            variant="subtle"
            pos="absolute"
            top={8}
            right={8}
            onClick={() => copy(plaintext)}
            aria-label="Copy token"
          >
            <Copy size={16} />
          </ActionIcon>
        </Box>
        <Button
          variant="subtle"
          leftSection={snippetOpen ? <ChevronDown size={16} /> : <ChevronRight size={16} />}
          onClick={snippet.toggle}
          fullWidth
          justify="flex-start"
        >
          Show MCP config snippet
        </Button>
        <Collapse in={snippetOpen}>
          <Box pos="relative">
            <Code block>{mcpSnippet}</Code>
            <ActionIcon
              variant="subtle"
              pos="absolute"
              top={8}
              right={8}
              onClick={() => copy(mcpSnippet)}
              aria-label="Copy snippet"
            >
              <Copy size={16} />
            </ActionIcon>
          </Box>
        </Collapse>
        <Group justify="flex-end" mt="sm">
          <Button onClick={onClose} color={copied ? "gray" : "blue"}>
            I copied the token — close
          </Button>
        </Group>
      </Stack>
    </Modal>
  );
}
