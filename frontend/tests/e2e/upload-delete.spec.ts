import { test } from "@playwright/test";

// SKIP: needs a configured role + bucket (e.g. MinIO sidecar in CI). Tests hand-rolled
// in Phase 4 once we have a CI-friendly S3-compatible test backend.
test.skip("upload + delete a file end-to-end", async () => {
  // Implementation:
  // 1. Login as admin
  // 2. Navigate to a role + bucket via sidebar
  // 3. Upload a small text file via the hidden file input
  // 4. Wait for the success toast
  // 5. Verify file appears in the list
  // 6. Click delete, confirm
  // 7. Verify file disappears + toast "Deleted 1 item"
});
