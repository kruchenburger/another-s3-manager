import { describe, expect, it } from "vitest";
import { createStorageStandIn } from "./storageStandIn";

describe("storage stand-in", () => {
  it("stores strings, enumerates keys and isolates instances", () => {
    const { storage } = createStorageStandIn();
    expect(storage.getItem("missing")).toBeNull();
    expect(storage.key(0)).toBeNull();
    storage.setItem("first", "");
    expect(storage.getItem("first")).toBe("");
    storage.setItem("second", "value");
    storage.setItem("first", "updated");
    expect(storage.length).toBe(2);
    expect(storage.getItem("first")).toBe("updated");
    expect(storage.key(0)).toBe("first");
    expect(storage.key(1)).toBe("second");
    expect(storage.key(2)).toBeNull();
    expect(createStorageStandIn().storage.length).toBe(0);
    storage.removeItem("first");
    storage.removeItem("missing");
    expect(storage.length).toBe(1);
    expect(storage.key(0)).toBe("second");
    storage.clear();
    expect(storage.length).toBe(0);
    expect(storage.getItem("second")).toBeNull();
  });

  it("coerces keys and values to strings", () => {
    const { storage } = createStorageStandIn();
    Reflect.apply(storage.setItem, storage, [42, false]);
    expect(storage.key(0)).toBe("42");
    expect(storage.getItem("42")).toBe("false");
    expect(Reflect.apply(storage.getItem, storage, [42])).toBe("false");
    Reflect.apply(storage.removeItem, storage, [42]);
    expect(storage.length).toBe(0);
  });

  it("lets enumeration, removal and clear hooks call the underlying operation", () => {
    const { storage, hooks } = createStorageStandIn();
    const calls: string[] = [];
    storage.setItem("first", "one");
    storage.setItem("second", "two");
    hooks.key = (index, read) => {
      calls.push(`key:${index}`);
      return read();
    };
    hooks.removeItem = (key, remove) => {
      calls.push(`remove:${key}`);
      remove();
    };
    hooks.clear = (clear) => {
      calls.push("clear");
      clear();
    };
    expect(storage.key(1)).toBe("second");
    storage.removeItem("first");
    expect(storage.getItem("first")).toBeNull();
    expect(storage.length).toBe(1);
    storage.clear();
    expect(storage.length).toBe(0);
    expect(calls).toEqual(["key:1", "remove:first", "clear"]);
  });

  it("preserves a captured read while a hook removes the entry", () => {
    const { storage, hooks } = createStorageStandIn();
    storage.setItem("job", "stale");
    let reads = 0;
    hooks.getItem = (key, read) => {
      reads++;
      const value = read();
      storage.removeItem(key);
      return value;
    };
    expect(storage.getItem("job")).toBe("stale");
    expect(reads).toBe(1);
    expect(storage.length).toBe(0);
  });

  it("allows writes between hook steps without recursively invoking the hook", () => {
    const { storage, hooks } = createStorageStandIn();
    const steps: string[] = [];
    hooks.setItem = (key, value, write) => {
      steps.push(`${key}:${value}:before:${storage.getItem(key)}`);
      write();
      steps.push(`${key}:after:${storage.getItem(key)}`);
    };
    storage.setItem("marker", "accepted");
    expect(steps).toEqual([
      "marker:accepted:before:null",
      "marker:after:accepted",
    ]);
    expect(storage.length).toBe(1);
  });

  it.each(["getItem", "setItem", "removeItem", "key", "clear"] as const)(
    "can deny %s without adding a storage item",
    (method) => {
      const { storage, hooks } = createStorageStandIn();
      storage.setItem("kept", "value");
      hooks[method] = () => {
        throw new Error("Storage denied");
      };
      const operations = {
        getItem: () => storage.getItem("kept"),
        setItem: () => storage.setItem("new", "value"),
        removeItem: () => storage.removeItem("kept"),
        key: () => storage.key(0),
        clear: () => storage.clear(),
      };
      expect(operations[method]).toThrow("Storage denied");
      expect(storage.length).toBe(1);
    },
  );
});
