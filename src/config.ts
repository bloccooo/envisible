const CONFIG_PATH = "bkey.config.json";

export type LocalStorageConfig = {
  backend: "local";
  root: string;
};

export type S3StorageConfig = {
  backend: "s3";
  bucket: string;
  region: string;
  endpoint?: string;    // override for MinIO, Backblaze B2, etc.
  accessKeyId: string;
  secretAccessKey: string;
};

export type R2StorageConfig = {
  backend: "r2";
  accountId: string;
  bucket: string;
  accessKeyId: string;
  secretAccessKey: string;
};

export type WebDavStorageConfig = {
  backend: "webdav";
  endpoint: string;   // e.g. https://dav.example.com/vault
  username?: string;
  password?: string;
};

export type StorageConfig =
  | LocalStorageConfig
  | S3StorageConfig
  | R2StorageConfig
  | WebDavStorageConfig;

export type BKeyConfig = {
  storage: StorageConfig;
};

export async function readConfig(): Promise<BKeyConfig | null> {
  const file = Bun.file(CONFIG_PATH);
  if (!(await file.exists())) return null;
  return file.json();
}

export async function writeConfig(config: BKeyConfig): Promise<void> {
  await Bun.write(CONFIG_PATH, JSON.stringify(config, null, 2));
}

export function configToBackendOptions(
  config: StorageConfig
): { type: string; options: Record<string, string> } {
  switch (config.backend) {
    case "local":
      return { type: "fs", options: { root: config.root } };
    case "s3": {
      const options: Record<string, string> = {
        bucket: config.bucket,
        region: config.region,
        access_key_id: config.accessKeyId,
        secret_access_key: config.secretAccessKey,
      };
      if (config.endpoint) options["endpoint"] = config.endpoint;
      return { type: "s3", options };
    }
    case "r2":
      return {
        type: "s3",
        options: {
          bucket: config.bucket,
          region: "auto",
          endpoint: `https://${config.accountId}.r2.cloudflarestorage.com`,
          access_key_id: config.accessKeyId,
          secret_access_key: config.secretAccessKey,
        },
      };
    case "webdav": {
      const options: Record<string, string> = { endpoint: config.endpoint };
      if (config.username) options["username"] = config.username;
      if (config.password) options["password"] = config.password;
      return { type: "webdav", options };
    }
  }
}
