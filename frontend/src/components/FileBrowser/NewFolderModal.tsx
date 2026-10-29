import { Alert, Button, Group, Modal, Stack, TextInput } from "@mantine/core";
import { useForm } from "@mantine/form";
import { useMutation, useQueryClient } from "@tanstack/react-query";
import { createFolder } from "@/features/files/api/filesApi";
import {
  exactJoin,
  validateName,
} from "@/features/files/utils/folderOperations";
import { getErrorMessage } from "@/utils/apiError";

interface Props {
  opened: boolean;
  bucket: string;
  role: string;
  path: string;
  onClose: () => void;
}
export function NewFolderModal({ opened, bucket, role, path, onClose }: Props) {
  const qc = useQueryClient();
  const form = useForm({
    initialValues: { name: "" },
    validate: { name: (name) => validateName(name, path) },
  });
  const mutation = useMutation({
    mutationFn: (name: string) =>
      createFolder(bucket, role, exactJoin(path, name)),
    onSuccess: () => {
      void qc.invalidateQueries({
        predicate: ({ queryKey: k }) =>
          k[0] === "files" &&
          (k[1] === "list" || k[1] === "search") &&
          k[2] === role &&
          k[3] === bucket,
      });
      form.reset();
      onClose();
    },
  });
  return (
    <Modal
      opened={opened}
      onClose={onClose}
      title="New folder"
      closeButtonProps={{ "aria-label": "Close" }}
    >
      <form onSubmit={form.onSubmit(({ name }) => mutation.mutate(name))}>
        <Stack>
          <TextInput
            label="Folder name"
            data-autofocus
            {...form.getInputProps("name")}
          />
          {mutation.error && (
            <Alert color="red" role="alert">
              {getErrorMessage(mutation.error)}
            </Alert>
          )}
          <Group justify="flex-end">
            <Button variant="default" onClick={onClose}>
              Cancel
            </Button>
            <Button type="submit" loading={mutation.isPending}>
              Create folder
            </Button>
          </Group>
        </Stack>
      </form>
    </Modal>
  );
}
