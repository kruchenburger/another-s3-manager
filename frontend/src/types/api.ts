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
}

export interface AppInfo {
  app_name: string;
  app_description: string;
  app_version: string;
}

export interface LoginResponse {
  user: User;
}
