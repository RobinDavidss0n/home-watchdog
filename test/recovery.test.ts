import assert from "node:assert/strict";
import { test } from "node:test";
import { env } from "../src/env.js";
import { parseActiveJobs } from "../src/ha-jobs.js";
import { createRecovery, decideOnFailedCheck, markHealthy } from "../src/recovery.js";

const MINUTE = 60 * 1000;

test("idle jobs restart on the third failed check, with a reboot first", () => {
  const recovery = createRecovery();

  assert.equal(decideOnFailedCheck(recovery, "idle", 0), "wait");
  assert.equal(decideOnFailedCheck(recovery, "idle", 1), "wait");
  assert.equal(decideOnFailedCheck(recovery, "idle", 2), "reboot");
});

test("a reboot that didn't help is followed by a reset, and resets repeat", () => {
  const recovery = createRecovery();

  for (let i = 0; i < 3; i++) decideOnFailedCheck(recovery, "idle", i);

  assert.equal(decideOnFailedCheck(recovery, "idle", 3), "wait");
  assert.equal(decideOnFailedCheck(recovery, "idle", 4), "wait");
  assert.equal(decideOnFailedCheck(recovery, "idle", 5), "reset");

  for (let i = 0; i < 2; i++) decideOnFailedCheck(recovery, "idle", i);
  assert.equal(decideOnFailedCheck(recovery, "idle", 6), "reset");
});

test("busy jobs defer until the busy limit, then count as failures", () => {
  const recovery = createRecovery();
  const limit = env.BUSY_JOBS_MAX_DEFER_MINUTES * MINUTE;

  assert.equal(decideOnFailedCheck(recovery, "busy", 0), "defer");
  assert.equal(decideOnFailedCheck(recovery, "busy", limit - 1), "defer");
  assert.equal(recovery.activeFails, 0);

  assert.equal(decideOnFailedCheck(recovery, "busy", limit), "wait");
  assert.equal(decideOnFailedCheck(recovery, "busy", limit + 1), "wait");
  assert.equal(decideOnFailedCheck(recovery, "busy", limit + 2), "reboot");
});

test("an unreachable agent defers for the shorter limit only", () => {
  const recovery = createRecovery();
  const limit = env.UNKNOWN_JOBS_MAX_DEFER_MINUTES * MINUTE;

  assert.ok(env.BUSY_JOBS_MAX_DEFER_MINUTES > env.UNKNOWN_JOBS_MAX_DEFER_MINUTES);
  assert.equal(decideOnFailedCheck(recovery, "unknown", 0), "defer");
  assert.equal(decideOnFailedCheck(recovery, "unknown", limit - 1), "defer");
  assert.equal(decideOnFailedCheck(recovery, "unknown", limit), "wait");
});

test("the limit runs from the start of the outage, not from the latest job", () => {
  const recovery = createRecovery();
  const limit = env.UNKNOWN_JOBS_MAX_DEFER_MINUTES * MINUTE;

  decideOnFailedCheck(recovery, "busy", 0);
  assert.equal(decideOnFailedCheck(recovery, "unknown", limit), "wait");
});

test("a healthy check clears everything", () => {
  const recovery = createRecovery();

  for (let i = 0; i < 3; i++) decideOnFailedCheck(recovery, "idle", i);
  decideOnFailedCheck(recovery, "idle", 3);
  markHealthy(recovery);

  assert.deepEqual(recovery, createRecovery());
  assert.equal(decideOnFailedCheck(recovery, "busy", 1000 * MINUTE), "defer");
});

test("parseActiveJobs finds unfinished jobs and their fields", () => {
  const output = [
    "ignore_conditions: []",
    "jobs:",
    "- created: 2026-11-02",
    "  done: false",
    "  name: backup_manager_full_backup",
    "  child_jobs:",
    "  - done: true",
    "    name: child_done",
    "- done: true",
    "  name: finished",
    ""
  ].join("\n");

  const jobs = parseActiveJobs(output);

  assert.equal(jobs.length, 1);
  assert.equal(jobs[0].name, "backup_manager_full_backup");
});

test("parseActiveJobs reports nothing when every job is done", () => {
  assert.deepEqual(parseActiveJobs("jobs:\n- done: true\n  name: finished\n"), []);
  assert.deepEqual(parseActiveJobs("jobs: []\n"), []);
});
