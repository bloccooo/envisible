// .bkey file: a tiny TOML-subset config committed to the repo
// project = "myapp"

export type BKeyFile = {
  project?: string;
};

export async function readBKeyFile(cwd = "."): Promise<BKeyFile> {
  const file = Bun.file(`${cwd}/.bkey`);
  if (!(await file.exists())) return {};

  const text = await file.text();
  const project = text.match(/^project\s*=\s*"([^"]+)"/m)?.[1];
  return { project };
}

export async function writeBKeyFile(project: string, cwd = "."): Promise<void> {
  await Bun.write(`${cwd}/.bkey`, `project = "${project}"\n`);
}
