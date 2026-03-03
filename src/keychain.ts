import keytar from "keytar";

const SERVICE = "bkey";

// Credentials are stored as a JSON blob per backend type.
// e.g. service="bkey", account="s3" → { accessKeyId, secretAccessKey }

export async function saveCredentials(
  backend: string,
  creds: Record<string, string>
): Promise<void> {
  await keytar.setPassword(SERVICE, backend, JSON.stringify(creds));
}

export async function loadCredentials(
  backend: string
): Promise<Record<string, string> | null> {
  const raw = await keytar.getPassword(SERVICE, backend);
  if (!raw) return null;
  try {
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

export async function deleteCredentials(backend: string): Promise<void> {
  await keytar.deletePassword(SERVICE, backend);
}
