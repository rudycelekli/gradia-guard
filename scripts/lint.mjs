import { readFileSync, readdirSync } from "node:fs";
import { extname, join } from "node:path";

const roots = ["src", "test", "scripts"];
const failures = [];

function visit(path) {
  for (const entry of readdirSync(path, { withFileTypes: true })) {
    const child = join(path, entry.name);
    if (entry.isDirectory()) visit(child);
    else if ([".ts", ".mjs"].includes(extname(entry.name))) {
      const lines = readFileSync(child, "utf8").split("\n");
      lines.forEach((line, index) => {
        if (/\s+$/.test(line)) failures.push(`${child}:${index + 1}: trailing whitespace`);
        if (line.includes("\t")) failures.push(`${child}:${index + 1}: tab character`);
        const unresolved = new RegExp(`\\b(?:${["TO", "DO"].join("")}|${["FIX", "ME"].join("")})\\b`);
        if (unresolved.test(line)) failures.push(`${child}:${index + 1}: unresolved marker`);
      });
    }
  }
}

for (const root of roots) visit(root);
if (failures.length) {
  process.stderr.write(`${failures.join("\n")}\n`);
  process.exitCode = 1;
}
