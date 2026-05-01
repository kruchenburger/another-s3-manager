import { test } from "@playwright/test";

// SKIP: needs a configured role + bucket. Will be enabled in Phase 4 with CI fixtures.
// The backend regression test in tests/test_main.py::test_download_file_with_colon_in_key
// already validates the API. This E2E will validate the full user flow.
test.skip("file with colon in name — full lifecycle (upload, navigate, download, delete)", async () => {
  // Implementation:
  // 1. Login + navigate to bucket
  // 2. Upload a file named "test:colon#hash?question.txt"
  // 3. Verify it appears in the list with the correct name
  // 4. Click download, verify download triggers (response 200, correct filename)
  // 5. Click delete, confirm, verify it disappears
});
