import { renderHook, act } from "@testing-library/react";
import { describe, it, expect, vi } from "vitest";
import type {
  InfiniteData,
  UseInfiniteQueryResult,
} from "@tanstack/react-query";
import type { ClientLoadPage } from "@/types/api";
import { useClientLoadDerived } from "@/features/files/hooks/clientLoadInfinite";

type Query = UseInfiniteQueryResult<InfiniteData<ClientLoadPage>, Error>;

const page: ClientLoadPage = {
  directories: [],
  files: [],
  truncated: true,
  next_token: "tok-1",
};

// Fabricate just the fields useClientLoadDerived touches: data.pages,
// hasNextPage, isFetchingNextPage, fetchNextPage. The wholesale cast is
// deliberate — a real UseInfiniteQueryResult has dozens of irrelevant fields.
function makeQuery(
  hasNextPage: boolean,
  fetchNextPage: (...args: unknown[]) => Promise<unknown>,
): Query {
  return {
    data: { pages: [page], pageParams: [undefined] },
    hasNextPage,
    isFetchingNextPage: false,
    fetchNextPage,
  } as unknown as Query;
}

describe("useClientLoadDerived loadAll completion", () => {
  it("resolves true when the level drains fully", async () => {
    const fetchNextPage = vi
      .fn()
      .mockResolvedValueOnce({ isError: false, hasNextPage: true })
      .mockResolvedValueOnce({ isError: false, hasNextPage: false });
    const { result } = renderHook(() =>
      useClientLoadDerived(makeQuery(true, fetchNextPage)),
    );
    let completed: boolean | undefined;
    await act(async () => {
      completed = await result.current.loadAll();
    });
    expect(completed).toBe(true);
    expect(fetchNextPage).toHaveBeenCalledTimes(2);
  });

  it("resolves false when stopped mid-drain", async () => {
    let stop: () => void = () => {};
    const fetchNextPage = vi.fn().mockImplementation(async () => {
      // Simulate the user clicking Stop while the second chunk is in flight.
      if (fetchNextPage.mock.calls.length === 2) stop();
      return { isError: false, hasNextPage: true };
    });
    const { result } = renderHook(() =>
      useClientLoadDerived(makeQuery(true, fetchNextPage)),
    );
    stop = result.current.stopLoadAll;
    let completed: boolean | undefined;
    await act(async () => {
      completed = await result.current.loadAll();
    });
    expect(completed).toBe(false);
    expect(fetchNextPage).toHaveBeenCalledTimes(2); // the drain halted early
  });

  it("resolves true immediately when the level is already fully loaded", async () => {
    const fetchNextPage = vi.fn();
    const { result } = renderHook(() =>
      useClientLoadDerived(makeQuery(false, fetchNextPage)),
    );
    let completed: boolean | undefined;
    await act(async () => {
      completed = await result.current.loadAll();
    });
    expect(completed).toBe(true);
    expect(fetchNextPage).not.toHaveBeenCalled();
  });
});
