/**
 * Decode a base64 blob from the GitHub API as UTF-8.
 *
 * `atob` returns a latin1 string, so any file containing non-ASCII bytes —
 * accented identifiers, non-English UI copy, emoji in comments — arrives
 * mojibaked. That silently corrupts the input to every downstream scanner and
 * to the LLM review, which is worse than failing loudly.
 */
export function decodeBase64Utf8(b64: string): string {
  const clean = b64.replace(/\s/g, "");
  try {
    const binary = atob(clean);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return new TextDecoder("utf-8").decode(bytes);
  } catch {
    return "";
  }
}
