import * as p from "@clack/prompts";
import { writeConfig, readConfig, type StorageConfig } from "../config";
import { saveCredentials } from "../keychain";

export async function cmdInit() {
  const existing = await readConfig();
  if (existing) {
    const overwrite = await p.confirm({
      message: "bkey.config.json already exists. Overwrite?",
      initialValue: false,
    });
    if (p.isCancel(overwrite) || !overwrite) {
      p.cancel("Init cancelled.");
      return;
    }
  }

  p.intro("bkey init");

  const backend = await p.select({
    message: "Choose a storage backend",
    options: [
      { value: "local",  label: "Local filesystem", hint: "good for testing" },
      { value: "s3",     label: "S3-compatible", hint: "AWS S3, MinIO, Backblaze B2, etc." },
      { value: "r2",     label: "Cloudflare R2" },
      { value: "webdav", label: "WebDAV", hint: "Nextcloud, ownCloud, etc." },
    ],
  });
  if (p.isCancel(backend)) { p.cancel("Cancelled."); return; }

  let storage: StorageConfig;

  if (backend === "local") {
    const root = await p.text({
      message: "Storage path",
      placeholder: "./bkey-storage",
      defaultValue: "./bkey-storage",
    });
    if (p.isCancel(root)) { p.cancel("Cancelled."); return; }
    storage = { backend: "local", root };

  } else if (backend === "s3") {
    const group = await p.group({
      bucket: () => p.text({ message: "Bucket name" }),
      region: () => p.text({ message: "Region", placeholder: "us-east-1", defaultValue: "us-east-1" }),
      endpoint: () => p.text({ message: "Endpoint URL (leave blank for AWS)", placeholder: "https://s3.example.com", defaultValue: "" }),
      accessKeyId: () => p.text({ message: "Access Key ID" }),
      secretAccessKey: () => p.password({ message: "Secret Access Key" }),
    }, { onCancel: () => { p.cancel("Cancelled."); process.exit(0); } });
    storage = {
      backend: "s3",
      bucket: group.bucket,
      region: group.region,
      ...(group.endpoint ? { endpoint: group.endpoint } : {}),
    };
    await saveCredentials("s3", {
      accessKeyId: group.accessKeyId,
      secretAccessKey: group.secretAccessKey,
    });

  } else if (backend === "r2") {
    const group = await p.group({
      accountId: () => p.text({ message: "Cloudflare Account ID" }),
      bucket: () => p.text({ message: "Bucket name" }),
      accessKeyId: () => p.text({ message: "R2 Access Key ID" }),
      secretAccessKey: () => p.password({ message: "R2 Secret Access Key" }),
    }, { onCancel: () => { p.cancel("Cancelled."); process.exit(0); } });
    storage = { backend: "r2", accountId: group.accountId, bucket: group.bucket };
    await saveCredentials("r2", {
      accessKeyId: group.accessKeyId,
      secretAccessKey: group.secretAccessKey,
    });

  } else {
    const group = await p.group({
      endpoint: () => p.text({ message: "WebDAV endpoint URL", placeholder: "https://dav.example.com/vault" }),
      username: () => p.text({ message: "Username (leave blank if none)", defaultValue: "" }),
      password: () => p.password({ message: "Password (leave blank if none)" }),
    }, { onCancel: () => { p.cancel("Cancelled."); process.exit(0); } });
    storage = { backend: "webdav", endpoint: group.endpoint };
    await saveCredentials("webdav", {
      ...(group.username ? { username: group.username } : {}),
      ...(group.password ? { password: group.password } : {}),
    });
  }

  await writeConfig({ storage });

  p.outro(`Config saved to bkey.config.json`);
}
