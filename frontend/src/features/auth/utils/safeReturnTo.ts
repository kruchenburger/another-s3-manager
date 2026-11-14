/** Client navigation guard; the server independently validates transaction targets. */
export function safeReturnTo(value: unknown): string {
  if (
    typeof value !== "string" ||
    new TextEncoder().encode(value).length > 2048 ||
    !value.startsWith("/") ||
    value.startsWith("//") ||
    value.startsWith("/\\") ||
    /[\u0000-\u001f\u007f]/.test(value)
  )
    return "/";
  return value;
}
