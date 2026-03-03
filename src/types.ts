// Fields marked "encrypted later" will become opaque strings once crypto is added.
// Collections are maps keyed by UUID so Automerge has stable CRDT keys.

export type Secret = {
  id: string;          // plaintext UUID (CRDT key)
  name: string;        // encrypted later
  value: string;       // encrypted later
  description: string; // encrypted later
  tags: string[];      // encrypted later
};

export type Project = {
  id: string;          // plaintext UUID (CRDT key)
  name: string;        // encrypted later
  secret_ids: string[]; // encrypted later
};

export type Workspace = {
  id: string;                        // plaintext UUID
  name: string;                      // encrypted later
  doc_version: number;               // plaintext monotonic counter
  projects: Record<string, Project>; // keyed by project UUID
  secrets: Record<string, Secret>;   // keyed by secret UUID
};
