// Runs the real watchdog with real Chromium in Docker against a fake HA and a fake
// Proxmox on localhost, so nothing here can touch the real ones. Uses the short
// development timings. Build the image first:
//   docker build --target development -t ha-watchdog-test .
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { AddressInfo } from "node:net";
import { describe, test } from "node:test";

const HEALTHY_TEXT = "I'm healthy :)";

type Fake = {
  healthy: boolean;
  jobs: "idle" | "busy" | "agent-down";
  rebootWorks: boolean;
  rebootFixes: boolean;
  rebootHealsAfterMs: number | null;
  resetWorks: boolean;
  calls: string[];
  notifications: string[];
};

const startFake = async (overrides: Partial<Fake>) => {

  const fake: Fake = {
    healthy: true,
    jobs: "idle",
    rebootWorks: true,
    rebootFixes: true,
    rebootHealsAfterMs: null,
    resetWorks: true,
    calls: [],
    notifications: [],
    ...overrides
  };

  const server = createServer((req, res) => {

    const json = (status: number, data: unknown) => {
      res.writeHead(status, { "Content-Type": "application/json" });
      res.end(JSON.stringify({ data }));
    };

    const url = req.url ?? "";

    if (url.startsWith("/health-check/0")) {
      res.writeHead(200, { "Content-Type": "text/html" });
      res.end(`<html><body>${fake.healthy ? HEALTHY_TEXT : "Loading data"}</body></html>`);

    } else if (url.endsWith("/agent/exec")) {
      if (fake.jobs === "agent-down") return json(500, null);
      json(200, { pid: 1 });

    } else if (url.includes("/agent/exec-status")) {
      const done = fake.jobs === "busy" ? "false" : "true";
      json(200, { exited: 1, exitcode: 0, "out-data": `jobs:\n- done: ${done}\n  name: some_job\n` });

    } else if (url.endsWith("/status/reboot")) {
      fake.calls.push("reboot");
      if (!fake.rebootWorks) return json(500, null);
      if (fake.rebootFixes) fake.healthy = true;
      if (fake.rebootHealsAfterMs !== null) setTimeout(() => { fake.healthy = true; }, fake.rebootHealsAfterMs);
      json(200, "UPID");

    } else if (url.endsWith("/status/reset")) {
      fake.calls.push("reset");
      if (!fake.resetWorks) return json(500, null);
      fake.healthy = true;
      json(200, "UPID");

    } else if (url.startsWith("/api/services/notify/")) {
      let body = "";
      req.on("data", chunk => body += chunk);
      req.on("end", () => {
        fake.notifications.push(JSON.parse(body).message);
        json(200, []);
      });

    } else {
      json(404, null);
    }
  });

  await new Promise<void>(resolve => server.listen(0, "127.0.0.1", resolve));

  return { fake, server, port: (server.address() as AddressInfo).port };
};

const runWatchdog = async (
  overrides: Partial<Fake>,
  until: (fake: Fake) => boolean,
  maxSeconds: number,
  onStart?: (fake: Fake) => void
) => {

  const { fake, server, port } = await startFake(overrides);
  const name = `ha-watchdog-test-${port}`;

  const container = spawn("docker", [
    "run", "--rm", "--name", name, "--network", "host",
    "-e", "NODE_ENV=development",
    "-e", "PROXMOX_TOKEN=test",
    "-e", "HA_TOKEN=test",
    "-e", `PROXMOX_HOST=http://127.0.0.1:${port}`,
    "-e", `HA_BASE_URL=http://127.0.0.1:${port}`,
    "ha-watchdog-test", "npx", "tsx", "src/main.ts"
  ], { stdio: "ignore" });

  const exited = new Promise(resolve => container.on("exit", resolve));

  onStart?.(fake);

  const deadline = Date.now() + maxSeconds * 1000;

  while (Date.now() < deadline && !until(fake))
    await new Promise(resolve => setTimeout(resolve, 500));

  // Long enough to catch a wrong extra call right after the expected one
  await new Promise(resolve => setTimeout(resolve, 3000));

  if (container.exitCode !== null) {
    server.closeAllConnections();
    server.close();

    throw new Error(`Container exited early with code ${container.exitCode}. The image may need building: docker build --target development -t ha-watchdog-test .`);
  }

  spawn("docker", ["kill", name], { stdio: "ignore" });
  await exited;

  server.closeAllConnections();
  server.close();

  return fake;
};

describe("recovery", { concurrency: 3 }, () => {

  test("healthy HA is left alone", async () => {
    const fake = await runWatchdog({}, () => false, 30);

    assert.deepEqual(fake.calls, []);
    assert.deepEqual(fake.notifications, []);
  });

  test("a stuck loading screen is fixed by a clean reboot", async () => {
    const fake = await runWatchdog({ healthy: false }, f => f.notifications.length > 0, 180);

    assert.deepEqual(fake.calls, ["reboot"]);
    assert.deepEqual(fake.notifications, ["HA Watchdog: Home Assistant was restarted (reboot) and has recovered successfully :)"]);
  });

  test("a reboot that doesn't help is followed by a reset", async () => {
    const fake = await runWatchdog({ healthy: false, rebootFixes: false }, f => f.notifications.length > 0, 300);

    assert.deepEqual(fake.calls, ["reboot", "reset"]);
    assert.deepEqual(fake.notifications, ["HA Watchdog: Home Assistant was restarted (reset) and has recovered successfully :)"]);
  });

  test("a reboot that can't be sent goes straight to a reset", async () => {
    const fake = await runWatchdog({ healthy: false, rebootWorks: false }, f => f.notifications.length > 0, 180);

    assert.deepEqual(fake.calls, ["reboot", "reset"]);
    assert.deepEqual(fake.notifications, ["HA Watchdog: Home Assistant was restarted (reset) and has recovered successfully :)"]);
  });

  test("an unreachable agent no longer blocks restarts forever", async () => {
    const fake = await runWatchdog({ healthy: false, jobs: "agent-down" }, f => f.notifications.length > 0, 300);

    assert.deepEqual(fake.calls, ["reboot"]);
  });

  test("a job stuck on not done no longer blocks restarts forever", async () => {
    const fake = await runWatchdog({ healthy: false, jobs: "busy" }, f => f.notifications.length > 0, 300);

    assert.deepEqual(fake.calls, ["reboot"]);
  });

  test("a job that finishes in time is not interrupted", async () => {
    const jobFinishes = (fake: Fake) => {
      setTimeout(() => {
        fake.jobs = "idle";
        fake.healthy = true;
      }, 25 * 1000);
    };

    const fake = await runWatchdog({ healthy: false, jobs: "busy" }, () => false, 50, jobFinishes);

    assert.deepEqual(fake.calls, []);
    assert.deepEqual(fake.notifications, []);
  });

  test("a failed restart is reported as failed, not as recovered", async () => {
    const fake = await runWatchdog({ healthy: false, rebootWorks: false, resetWorks: false }, f => f.notifications.length > 0, 180);

    assert.deepEqual(fake.calls, ["reboot", "reset"]);
    assert.deepEqual(fake.notifications, ["HA Watchdog: Home Assistant is unhealthy and could not be restarted :("]);
  });

  test("a slow boot after a reboot is not power-cut", async () => {
    const fake = await runWatchdog({ healthy: false, jobs: "agent-down", rebootFixes: false, rebootHealsAfterMs: 95 * 1000 }, f => f.notifications.length > 0, 300);

    assert.deepEqual(fake.calls, ["reboot"]);
    assert.deepEqual(fake.notifications, ["HA Watchdog: Home Assistant was restarted (reboot) and has recovered successfully :)"]);
  });

  test("a failed restart is told once, and so is recovering by itself", async () => {
    const healsAfterTheFirstMessage = (fake: Fake) => {
      let toldAt: number | null = null;

      const interval = setInterval(() => {

        if (fake.notifications.length !== 1) return;

        toldAt ??= Date.now();

        if (35 * 1000 > Date.now() - toldAt) return;

        fake.healthy = true;
        clearInterval(interval);
      }, 500);

      // A container that exits early must not leave this holding the test run open
      interval.unref();
    };

    const fake = await runWatchdog({ healthy: false, rebootWorks: false, resetWorks: false }, f => f.notifications.length >= 2, 240, healsAfterTheFirstMessage);

    assert.deepEqual(fake.notifications, [
      "HA Watchdog: Home Assistant is unhealthy and could not be restarted :(",
      "HA Watchdog: Home Assistant is healthy again without a restart :)"
    ]);
  });
});
