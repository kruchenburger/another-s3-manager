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
  tour_seen_v1: boolean;
  app_name: string;
  app_version: string;
  allowed_roles: string[];
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

export interface Ban {
  username: string;
  banned_until: number; // unix epoch seconds
  banned_at: number;
  reason: string;
}

export interface AdminUser {
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
  items_per_page: number;
  enable_lazy_loading: boolean;
  max_file_size: number;
  disable_deletion: boolean;
  auto_inline_extensions?: string[];
  data_dir?: string;
  is_read_only?: boolean;
  current_role?: string;
  password_min_length: number;
  password_min_uppercase: number;
  password_min_lowercase: number;
  password_min_digits: number;
  password_min_special: number;
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
