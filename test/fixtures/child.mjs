process.stdout.write("visible output\n");
process.stderr.write("visible error\n");
if (process.argv[2] === "signal") process.kill(process.pid, "SIGTERM");
else process.exitCode = Number(process.argv[2] ?? "0");
