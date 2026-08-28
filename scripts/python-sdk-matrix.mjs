import { spawnSync } from "node:child_process";

const completed = spawnSync(
  process.execPath,
  [
    "--test",
    "--test-name-pattern=pinned Python",
    "dist/test/credentialless-runtime.test.js",
  ],
  {
    env: { ...process.env, GRADIA_GUARD_TEST_PYTHON_SDKS: "1" },
    stdio: "inherit",
  },
);

if (completed.error) throw completed.error;
process.exit(completed.status ?? 1);
