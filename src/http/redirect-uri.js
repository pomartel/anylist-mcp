export function validRedirectUri(value) {
  if (typeof value !== "string" || !value || /[\s\\#\u0000-\u001f\u007f]/u.test(value)) return false;
  try {
    const url = new URL(value);
    if (url.username || url.password) return false;
    if (url.protocol === "https:") return value.startsWith("https://");
    return value.startsWith("http://") && ["127.0.0.1", "[::1]", "localhost"].includes(url.hostname);
  } catch {
    return false;
  }
}
