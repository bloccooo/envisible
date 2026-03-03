import * as A from "@automerge/automerge";
import { randomUUIDv7 } from "bun";
import type { Secret, Workspace } from "./types";

export function addSecret(
  doc: A.Doc<Workspace>,
  fields: Omit<Secret, "id">
): A.Doc<Workspace> {
  const id = randomUUIDv7();
  return A.change(doc, `add secret ${fields.name}`, (d) => {
    d.secrets[id] = { id, ...fields };
  });
}

export function removeSecret(
  doc: A.Doc<Workspace>,
  id: string
): A.Doc<Workspace> {
  return A.change(doc, `remove secret ${id}`, (d) => {
    delete d.secrets[id];
    // Remove from any projects that reference it
    for (const project of Object.values(d.projects)) {
      const idx = project.secret_ids.indexOf(id);
      if (idx !== -1) project.secret_ids.splice(idx, 1);
    }
  });
}

export function updateSecret(
  doc: A.Doc<Workspace>,
  id: string,
  fields: Omit<Secret, "id">
): A.Doc<Workspace> {
  return A.change(doc, `update secret ${id}`, (d) => {
    const s = d.secrets[id];
    if (!s) throw new Error(`Secret ${id} not found`);
    s.name = fields.name;
    s.value = fields.value;
    s.description = fields.description;
    s.tags.splice(0, s.tags.length, ...fields.tags);
  });
}

export function listSecrets(doc: A.Doc<Workspace>): Secret[] {
  return Object.values(doc.secrets);
}
