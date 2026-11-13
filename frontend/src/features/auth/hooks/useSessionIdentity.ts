import { useEffect, useSyncExternalStore } from "react";
import { QueryClient, useQueryClient } from "@tanstack/react-query";
import { fetchMe } from "@/features/auth/api/authApi";
import { clearCsrfToken, setCsrfToken } from "@/utils/csrf";
import type { MeResponse } from "@/types/api";

const key = ["auth", "me"] as const;
const signalKey = "asm-auth-changed";
type Listener = () => void;
const coordinators = new WeakMap<QueryClient, SessionIdentity>();

export class SessionIdentity {
  blocked = false;
  generation = 0;
  identity: string | undefined;
  private listeners = new Set<Listener>();
  private pending: Promise<void> | undefined;
  private rerun = false;
  constructor(private client: QueryClient) {
    const generations = new WeakMap<object, number>();
    const wrapped = new WeakSet<object>();
    client.getMutationCache().subscribe(({ mutation }) => {
      if (!mutation) return;
      // Authentication responses coordinate their own cookie-jar replacement.
      if (mutation.options.meta?.authentication === true) return;
      const execute = mutation.options.mutationFn;
      if (!execute || wrapped.has(execute)) return;
      const generation = generations.get(mutation) ?? this.generation;
      generations.set(mutation, generation);
      const guarded: typeof execute = async (...args) => {
        if (this.blocked || generation !== this.generation)
          throw new Error("Session changed");
        const result = await execute(...args);
        if (generation !== this.generation)
          throw new Error("Superseded session response");
        return result;
      };
      wrapped.add(guarded);
      mutation.setOptions({ ...mutation.options, mutationFn: guarded });
    });
  }
  subscribe = (listener: Listener) => {
    this.listeners.add(listener);
    return () => {
      this.listeners.delete(listener);
    };
  };
  snapshot = () => this.blocked;
  private notify() {
    this.listeners.forEach((listener) => listener());
  }
  async accept(me: MeResponse, generation: number) {
    if (generation !== this.generation)
      throw new Error("Superseded session response");
    let ownsBlock = false;
    if (
      this.identity &&
      me.session_identity &&
      this.identity !== me.session_identity
    ) {
      ownsBlock = !this.blocked;
      generation = ++this.generation;
      this.blocked = true;
      clearCsrfToken();
      this.notify();
      await this.client.cancelQueries({
        predicate: (q) => q.queryKey[0] !== "auth",
      });
      this.client.removeQueries({
        predicate: (q) =>
          q.queryKey[0] !== "auth" && q.queryKey[0] !== "app-info",
      });
      this.client.getMutationCache().clear();
    }
    if (generation !== this.generation)
      throw new Error("Superseded session response");
    this.identity = me.session_identity;
    if (
      me.session_identity &&
      sessionStorage.getItem("asm-session-identity") !== me.session_identity
    ) {
      sessionStorage.setItem("asm-session-identity", me.session_identity);
      try {
        localStorage.setItem(signalKey, String(Date.now()) + Math.random());
      } catch {
        /* Recheck on focus. */
      }
    }
    setCsrfToken(me.csrf_token);
    if (ownsBlock) {
      this.client.setQueryData(key, me);
      this.blocked = false;
      this.notify();
    }
    return me;
  }
  refresh = (broadcast = false): Promise<void> => {
    if (broadcast) {
      // The signal contains neither account identifiers nor credentials.
      try {
        localStorage.setItem(signalKey, String(Date.now()) + Math.random());
      } catch {
        /* Focus recovery remains available. */
      }
    }
    if (this.pending) {
      this.rerun = true;
      ++this.generation;
      clearCsrfToken();
      return this.pending;
    }
    this.blocked = true;
    this.notify();
    clearCsrfToken();
    this.pending = (async () => {
      try {
        do {
          this.rerun = false;
          ++this.generation;
          await this.client.cancelQueries();
          for (const mutation of this.client.getMutationCache().getAll()) {
            if (mutation.options.meta?.authentication === true) continue;
            mutation.setOptions({
              ...mutation.options,
              mutationFn: async () => {
                throw new Error("Session changed");
              },
              onSuccess: undefined,
              onError: undefined,
              onSettled: undefined,
            });
          }
          this.client.getMutationCache().clear();
          this.client.removeQueries({
            predicate: (q) =>
              q.queryKey[0] !== "auth" && q.queryKey[0] !== "app-info",
          });
          // Preserve the established login/reset seam while actions are gated.
          await this.client.resetQueries({ queryKey: key });
          const generation = this.generation;
          try {
            await this.client.fetchQuery({
              queryKey: key,
              staleTime: 0,
              retry: false,
              queryFn: async () => this.accept(await fetchMe(), generation),
            });
          } catch {
            this.identity = undefined;
            clearCsrfToken();
          }
        } while (this.rerun);
      } finally {
        this.pending = undefined;
        this.blocked = false;
        this.notify();
      }
    })();
    return this.pending;
  };

  logout() {
    ++this.generation;
    this.identity = undefined;
    clearCsrfToken();
    this.client.clear();
    try {
      localStorage.setItem(signalKey, String(Date.now()) + Math.random());
    } catch {
      /* Recheck on focus. */
    }
  }
}

export function sessionCoordinator(client: QueryClient) {
  let coordinator = coordinators.get(client);
  if (!coordinator) {
    coordinator = new SessionIdentity(client);
    coordinators.set(client, coordinator);
  }
  return coordinator;
}

export function useSessionIdentity() {
  const coordinator = sessionCoordinator(useQueryClient());
  const blocked = useSyncExternalStore(
    coordinator.subscribe,
    coordinator.snapshot,
  );
  useEffect(() => {
    const refresh = () => {
      void coordinator.refresh();
    };
    const signal = (event: StorageEvent) => {
      if (event.key === signalKey) refresh();
    };
    window.addEventListener("focus", refresh);
    window.addEventListener("pageshow", refresh);
    window.addEventListener("storage", signal);
    return () => {
      window.removeEventListener("focus", refresh);
      window.removeEventListener("pageshow", refresh);
      window.removeEventListener("storage", signal);
    };
  }, [coordinator]);
  return { coordinator, blocked };
}
