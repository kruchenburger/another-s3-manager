export type Theme = "light" | "dark" | "auto";

export interface User {
  username: string;
  is_admin: boolean;
}

export interface MeResponse {
  username: string;
  is_admin: boolean;
  csrf_token: string;
  theme: Theme;
  app_name: string;
  app_version: string;
  allowed_roles: string[];
  /** User's chosen default role. Computed: explicit choice if still in
   *  allowed_roles, else first of allowed_roles, else null. Set via
   *  PUT /api/me/default-role. */
  default_role: string | null;
  /** True when admin created or reset the user's password and required them
   *  to change it on next login. Cleared by PUT /api/me/password on success.
   *  Frontend RequireFreshPassword guard redirects to /change-password while
   *  this is true. */
  must_change_password: boolean;
  /**
   * True when admin set `disable_deletion: true` in config.json OR the
   * `DISABLE_DELETION` env var is set. UI uses this to disable delete controls
   * before the user clicks (avoids the "click → 403" UX dead-end).
   */
  disable_deletion: boolean;
  /**
   * Server-enforced per-file upload limit in bytes. Surfaced to the client so
   * uploads that would fail server-side can be rejected pre-flight with a
   * useful "file X is N MB, limit is M MB" message — without this the user
   * just sees a generic 400 after the file has already streamed over the wire.
   */
  max_file_size: number;
}

export interface AppInfo {
  app_name: string;
  app_description: string;
  app_version: string;
}

export interface LoginResponse {
  user: User;
}

export type BucketList = string[];

export interface FileEntry {
  name: string;
  is_directory: boolean;
  size: number;
  last_modified?: string; // ISO string, only for files
}

export interface FileListResponse {
  files: FileEntry[];
  path: string;
  total_count: number;
}

/**
 * Response from GET /api/buckets/.../files?client_load=1. The /v2 UI loads one
 * of these chunks (up to max_client_load objects) into memory and paginates
 * client-side. `truncated` is true when S3 has more objects than this chunk;
 * `next_token` resumes from where this chunk stopped.
 *
 *  - `directories` is populated ONLY on the first chunk (no `continuation_token`).
 *  - `next_token` is the opaque S3 continuation token for the next chunk, or
 *    `null` when the folder is fully drained.
 */
export interface ClientLoadPage {
  directories: FileEntry[];
  files: FileEntry[];
  truncated: boolean;
  next_token: string | null;
}

export interface Ban {
  username: string;
  banned_until: number; // unix epoch seconds
  banned_at: number;
  reason: string;
}

export interface AdminUser {
  id: number;
  username: string;
  is_admin: boolean;
  allowed_roles: string[];
  // created_at: not currently rendered — backend returns it but frontend
  // doesn't display it. Add back with a "Created" column when wanted.
}

export interface AdminUsersResponse {
  users: AdminUser[];
  available_roles: string[];
}

export interface CreateUserPayload {
  username: string;
  password: string;
  is_admin: boolean;
  allowed_roles: string[];
  must_change_password?: boolean;
}

export interface UpdateUserPayload {
  is_admin?: boolean;
  allowed_roles?: string[];
}

export interface AppRole {
  name: string;
  type: "default" | "profile" | "assume_role" | "credentials" | "s3_compatible";
  description?: string;
  // Type-specific fields (most are optional depending on type):
  profile_name?: string;
  role_arn?: string;
  access_key_id?: string;
  secret_access_key?: string;
  region?: string;
  endpoint_url?: string;
  use_ssl?: boolean;
  verify_ssl?: boolean;
  addressing_style?: "auto" | "virtual" | "path";
  allowed_buckets?: string[];
}

export interface PasswordPolicy {
  password_min_length: number;
  password_min_uppercase: number;
  password_min_lowercase: number;
  password_min_digits: number;
  password_min_special: number;
}

export interface AppConfig {
  roles: AppRole[];
  default_role?: string;
  enable_lazy_loading: boolean;
  max_file_size: number;
  // Cap on objects the /v2 UI loads into memory before showing "Load more".
  max_client_load: number;
  // Presigned URL lifetime settings (seconds). default_ttl is granted when no
  // explicit expires_in is requested; max_ttl bounds per-link overrides.
  presigned_url_default_ttl: number;
  presigned_url_max_ttl: number;
  disable_deletion: boolean;
  // Which text files preview inline in the UI (media/pdf always preview).
  preview_text_extensions?: string[];
  // Which uploads get Content-Disposition: inline (open in browser via CDN).
  upload_inline_extensions?: string[];
  data_dir?: string;
  is_read_only?: boolean;
  current_role?: string;
  password_min_length: number;
  password_min_uppercase: number;
  password_min_lowercase: number;
  password_min_digits: number;
  password_min_special: number;
  // MCP server settings
  mcp_enabled: boolean;
  mcp_disable_writes: boolean;
  mcp_text_extensions: string[];
  mcp_global_max_read_bytes: number;
}

export interface ChangeMyPasswordPayload {
  current_password: string;
  new_password: string;
}

export interface ApiToken {
  id: number;
  name: string;
  is_read_only: boolean;
  max_read_bytes: number;
  created_at: string;
  last_used_at: string | null;
  revoked_at: string | null;
}

export interface ApiTokenWithOwner extends ApiToken {
  owner_username: string;
}

export interface ApiTokenWithPlaintext extends ApiToken {
  token_plaintext: string;
}

export interface CreateTokenPayload {
  name: string;
  is_read_only: boolean;
  max_read_bytes: number;
}

export interface AdminCreateTokenPayload extends CreateTokenPayload {
  user_id: number;
}

export interface MyTokensResponse {
  tokens: ApiToken[];
  used: number;
  limit: number;
}

export interface AdminTokensResponse {
  tokens: ApiTokenWithOwner[];
}

// Phase 6a-1: PUT /api/me/tokens/{id} and PUT /api/admin/tokens/{id} bodies.
// All fields optional; backend rejects empty bodies with 400.
export interface UpdateTokenPayload {
  name?: string;
  is_read_only?: boolean;
  max_read_bytes?: number;
}

// Admin uses the same shape as self-serve. Aliased for call-site clarity.
export type AdminUpdateTokenPayload = UpdateTokenPayload;
