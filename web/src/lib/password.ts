/** Random passphrase-like password from the Web Crypto RNG (no ambiguous characters). */
export function generatePassword(length = 20): string {
  const alphabet = "abcdefghjkmnpqrstuvwxyzABCDEFGHJKMNPQRSTUVWXYZ23456789-_";
  const out: string[] = [];
  const buf = new Uint32Array(length);
  crypto.getRandomValues(buf);
  // 2^32 is not a multiple of the alphabet size; reject the biased tail.
  const limit = Math.floor(0x1_0000_0000 / alphabet.length) * alphabet.length;
  let i = 0;
  while (out.length < length) {
    if (i >= buf.length) {
      crypto.getRandomValues(buf);
      i = 0;
    }
    const v = buf[i++] as number;
    if (v < limit) out.push(alphabet[v % alphabet.length] as string);
  }
  return out.join("");
}

/** Client-side mirror of the server policy (the server decides). */
export function passwordProblem(username: string, password: string): string | null {
  if ([...password].length < 12) return "Не короче 12 символов";
  if (new TextEncoder().encode(password).length > 256) return "Не длиннее 256 байт";
  if (username && password.toLowerCase().includes(username.toLowerCase())) return "Пароль не должен содержать имя пользователя";
  if (new Set(password).size === 1) return "Пароль не может состоять из одного повторяющегося символа";
  return null;
}
