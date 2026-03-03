import { loadOrCreate, persist } from "./src/store";
import { addSecret, listSecrets } from "./src/secrets";
import { addProject, listProjects } from "./src/projects";
import { localBackend } from "./src/storage";

const backend = localBackend(".");
let doc = await loadOrCreate(backend);

// Seed demo data on first run
if (Object.keys(doc.secrets).length === 0) {
  doc = addSecret(doc, {
    name: "DATABASE_URL",
    value: "postgres://localhost:5432/myapp",
    description: "Main Postgres connection string",
    tags: ["database"],
  });
  doc = addSecret(doc, {
    name: "API_KEY",
    value: "sk-abc123",
    description: "Payment provider API key",
    tags: ["payments"],
  });
  doc = addSecret(doc, {
    name: "REDIS_URL",
    value: "redis://localhost:6379",
    description: "Redis cache",
    tags: ["cache"],
  });

  const secrets = listSecrets(doc);
  const byName = (name: string) => secrets.find((s) => s.name === name)!.id;

  doc = addProject(doc, "backend", [
    byName("DATABASE_URL"),
    byName("API_KEY"),
    byName("REDIS_URL"),
  ]);
  doc = addProject(doc, "frontend", [byName("API_KEY")]);
}

console.log("\nSecrets:", listSecrets(doc).map((s) => s.name));
console.log("Projects:", listProjects(doc).map((p) => `${p.name} (${p.secret_ids.length} secrets)`));

await persist(doc, backend);
