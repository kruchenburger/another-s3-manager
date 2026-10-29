import { useEffect, useRef, useState } from "react";
import type {
  MoveItem,
  MovePreflight,
  MoveRequest,
  MoveStartRequest,
} from "@/types/api";
import { movePreflight, startMove } from "@/features/files/api/filesApi";
import { useMoveJobs } from "@/features/files/jobs/MoveJobsProvider";
import {
  newMoveAction,
  targetError,
} from "@/features/files/utils/folderOperations";
import { getErrorMessage } from "@/utils/apiError";

export function useFolderOperations(
  bucket: string,
  role: string,
  path: string,
  disabled: boolean,
  onStarted?: () => void,
) {
  const { add, disableDeletion: storeDisabled } = useMoveJobs();
  const [newFolder, setNewFolder] = useState(false);
  const [picker, setPicker] = useState<MoveItem[] | null>(null);
  const [confirmation, setConfirmation] = useState<{
    action: MoveStartRequest;
    preflight: MovePreflight;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const version = useRef(0);
  const inFlight = useRef(false);
  const close = () => {
    version.current++;
    setPicker(null);
    setConfirmation(null);
    setError(null);
    setBusy(false);
  };
  useEffect(() => {
    close();
    setNewFolder(false);
  }, [bucket, role, path]);
  useEffect(
    () => () => {
      version.current++;
    },
    [],
  );
  const choose = async (request: MoveRequest) => {
    if (disabled || storeDisabled || inFlight.current) return;
    const reason = targetError(request.items, request.destination);
    if (reason) {
      setError(reason);
      return;
    }
    const revision = ++version.current;
    setBusy(true);
    setError(null);
    try {
      const preflight = await movePreflight(bucket, role, request);
      if (revision !== version.current) return;
      setConfirmation({ action: newMoveAction(request), preflight });
    } catch (e) {
      if (revision === version.current) setError(getErrorMessage(e));
    } finally {
      if (revision === version.current) setBusy(false);
    }
  };
  const confirm = async () => {
    if (
      !confirmation ||
      disabled ||
      storeDisabled ||
      inFlight.current ||
      confirmation.preflight.blocked_reason ||
      confirmation.preflight.conflicts.length
    )
      return;
    inFlight.current = true;
    setBusy(true);
    setError(null);
    const revision = version.current;
    try {
      const response = await startMove(bucket, role, confirmation.action);
      add({
        job_id: response.job_id,
        bucket,
        role,
        items: confirmation.action.items,
        destination: confirmation.action.destination,
      });
      if (revision === version.current) {
        onStarted?.();
        close();
      }
    } catch (e) {
      if (revision === version.current) setError(getErrorMessage(e));
    } finally {
      inFlight.current = false;
      if (revision === version.current) setBusy(false);
    }
  };
  return {
    newFolder,
    setNewFolder,
    picker,
    open: (items: MoveItem[]) => {
      if (!disabled) {
        close();
        setPicker(items);
      }
    },
    confirmation,
    choose,
    confirm,
    close,
    busy,
    error,
  };
}
