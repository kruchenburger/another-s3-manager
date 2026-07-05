/** A File paired with its relative path inside a dropped/picked folder.
 *
 * For top-level files (loose drag-drop, single-file upload button), `relativePath`
 * equals `file.name`. For files coming from a folder, it carries the full path
 * inside the folder, e.g. `"docs/sub/file.txt"`.
 *
 * The S3 key for the uploaded object is then computed as
 * `currentBrowserPath + "/" + relativePath` (or just `relativePath` at the root).
 */
export interface FileWithRelativePath {
  file: File;
  relativePath: string;
}

/** Read one batch of children from a directory reader.
 *
 * The browser API returns the callback-style result. We promisify it so the
 * walker can `await` instead of nesting callbacks.
 */
function readBatch(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  return new Promise((resolve, reject) => {
    reader.readEntries(
      (entries) => resolve(entries),
      // The errorCallback is optional in the spec but browsers will sometimes
      // surface I/O errors here (e.g. user revokes filesystem permission
      // mid-walk). Reject so the caller's error path handles it.
      (err) => reject(err),
    );
  });
}

/** Drain a FileSystemDirectoryReader by repeatedly calling readEntries until
 * it returns an empty array.
 *
 * The real browser API is paginated — readEntries can return a partial batch
 * even on the first call. A naive single read drops files silently. */
async function drainReader(reader: FileSystemDirectoryReader): Promise<FileSystemEntry[]> {
  const all: FileSystemEntry[] = [];
  // eslint-disable-next-line no-constant-condition
  while (true) {
    const batch = await readBatch(reader);
    if (batch.length === 0) break;
    all.push(...batch);
  }
  return all;
}

/** Read a single file out of a FileSystemFileEntry. */
function readFile(entry: FileSystemFileEntry): Promise<File> {
  return new Promise((resolve, reject) => {
    entry.file(
      (file) => resolve(file),
      (err) => reject(err),
    );
  });
}

/** Recursively walk one FileSystemEntry, returning every file inside with its
 * relative path prefixed by `pathPrefix`.
 *
 * The relativePath always starts with the top-level dropped name. For a single
 * file dropped at the root, it's just the file name. For a folder dropped at
 * the root, every file inside is prefixed by the folder's name. */
async function walkEntry(
  entry: FileSystemEntry,
  pathPrefix: string,
): Promise<FileWithRelativePath[]> {
  if (entry.isFile) {
    const fileEntry = entry as FileSystemFileEntry;
    const file = await readFile(fileEntry);
    const relativePath = pathPrefix ? `${pathPrefix}/${entry.name}` : entry.name;
    return [{ file, relativePath }];
  }

  if (entry.isDirectory) {
    const dirEntry = entry as FileSystemDirectoryEntry;
    const childPrefix = pathPrefix ? `${pathPrefix}/${entry.name}` : entry.name;
    const children = await drainReader(dirEntry.createReader());
    const results = await Promise.all(children.map((child) => walkEntry(child, childPrefix)));
    return results.flat();
  }

  // Spec says exactly one of isFile/isDirectory is true. Future-proof against
  // a new entry kind (e.g. symlinks if a vendor extension lands) by silently
  // skipping rather than throwing — the user's other files should still upload.
  return [];
}

/** Expand a DataTransferItemList from a drag-drop into a flat list of files
 * annotated with their relative paths.
 *
 * Modern browsers expose `webkitGetAsEntry()` on each item. Folders return a
 * FileSystemDirectoryEntry that this function recurses into; files return a
 * FileSystemFileEntry that we read once and emit.
 *
 * For items whose `webkitGetAsEntry()` returns null (rare — older browsers,
 * some mobile WebViews), we fall back to `getAsFile()` and treat the file as
 * top-level. Items whose `kind !== "file"` (e.g. dragged text) are skipped. */
export async function expandDirectoryEntries(
  items: DataTransferItem[],
): Promise<FileWithRelativePath[]> {
  const results: FileWithRelativePath[] = [];
  for (const item of items) {
    if (item.kind !== "file") continue;
    const entry = item.webkitGetAsEntry ? item.webkitGetAsEntry() : null;
    if (entry) {
      const branch = await walkEntry(entry, "");
      results.push(...branch);
    } else {
      // Fallback: legacy browser path. The item is a file but we can't probe
      // for folder-ness, so we treat it as top-level.
      const file = item.getAsFile();
      if (file) {
        results.push({ file, relativePath: file.name });
      }
    }
  }
  return results;
}

/** Project a FileList from an `<input webkitdirectory>` element into
 * `FileWithRelativePath[]`.
 *
 * Browsers populate `File.webkitRelativePath` for files picked via a
 * webkitdirectory input — that field IS the relative path we want. If it's
 * empty (older browser, or the input wasn't webkitdirectory), we fall back
 * to file.name. */
export function filesFromFolderInput(files: FileList): FileWithRelativePath[] {
  const results: FileWithRelativePath[] = [];
  for (let i = 0; i < files.length; i++) {
    const file = files[i];
    const relativePath = file.webkitRelativePath || file.name;
    results.push({ file, relativePath });
  }
  return results;
}
