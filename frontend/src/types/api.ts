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
