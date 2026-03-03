import * as A from "@automerge/automerge";
import { randomUUIDv7 } from "bun";
import type { Workspace } from "./types";
import type { StorageBackend } from "./storage";

export async function loadOrCreate(
  backend: StorageBackend
): Promise<A.Doc<Workspace>> {
  const binary = await backend.pull();

  if (binary) {
    return A.load<Workspace>(binary);
  }

  let doc = A.init<Workspace>();
  doc = A.change(doc, "init workspace", (d) => {
    d.id = randomUUIDv7();
    d.name = "my-workspace";
    d.doc_version = 0;
    d.projects = {};
    d.secrets = {};
  });
  return doc;
}

export async function persist(
  doc: A.Doc<Workspace>,
  backend: StorageBackend
): Promise<void> {
  const binary = A.save(doc);
  await backend.push(binary);
}
