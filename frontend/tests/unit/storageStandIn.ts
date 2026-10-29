export interface StorageHooks {
  getItem?: (key: string, read: () => string | null) => string | null;
  setItem?: (key: string, value: string, write: () => void) => void;
  removeItem?: (key: string, remove: () => void) => void;
  clear?: (clear: () => void) => void;
  key?: (index: number, read: () => string | null) => string | null;
}

export function createStorageStandIn() {
  const entries = new Map<string, string>();
  const hooks: StorageHooks = {};
  const storage: Storage = {
    get length() {
      return entries.size;
    },
    getItem(key) {
      key = String(key);
      const read = () => entries.get(key) ?? null;
      return hooks.getItem ? hooks.getItem(key, read) : read();
    },
    setItem(key, value) {
      key = String(key);
      value = String(value);
      const write = () => {
        entries.set(key, value);
      };
      if (hooks.setItem) hooks.setItem(key, value, write);
      else write();
    },
    removeItem(key) {
      key = String(key);
      const remove = () => {
        entries.delete(key);
      };
      if (hooks.removeItem) hooks.removeItem(key, remove);
      else remove();
    },
    clear() {
      const clear = () => entries.clear();
      if (hooks.clear) hooks.clear(clear);
      else clear();
    },
    key(index) {
      const read = () => Array.from(entries.keys())[index] ?? null;
      return hooks.key ? hooks.key(index, read) : read();
    },
  };
  return { storage, hooks };
}
