import type { AppConfig } from "@/types/api";

/**
 * Strip derived/runtime fields the backend adds to GET /api/config responses
 * but does NOT expect on POST. Notably:
 *   - `data_dir`: response is the resolved current value; persisting it would
 *     latch the path into config.json and override env-var resolution on
 *     future deployments (constants.py:get_data_dir falls back to config).
 *   - `current_role`: response-only, computed per-request from per-user perms.
 *   - `is_read_only`: filesystem capability check, never config data.
 *
 * Vanilla admin.html builds the save payload via explicit allowlist for the
 * same reason — replicate that contract here.
 */
export function toWritableConfig(config: AppConfig): AppConfig {
  return {
    roles: config.roles,
    default_role: config.default_role,
    items_per_page: config.items_per_page,
    enable_lazy_loading: config.enable_lazy_loading,
    max_file_size: config.max_file_size,
    disable_deletion: config.disable_deletion,
    auto_inline_extensions: config.auto_inline_extensions,
    password_min_length: config.password_min_length,
    password_min_uppercase: config.password_min_uppercase,
    password_min_lowercase: config.password_min_lowercase,
    password_min_digits: config.password_min_digits,
    password_min_special: config.password_min_special,
  };
}
