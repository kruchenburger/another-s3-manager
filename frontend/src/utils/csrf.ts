const KEY = "csrf_token";

export function getCsrfToken(): string | null {
  return sessionStorage.getItem(KEY);
}

export function setCsrfToken(token: string): void {
  sessionStorage.setItem(KEY, token);
}

export function clearCsrfToken(): void {
  sessionStorage.removeItem(KEY);
}
