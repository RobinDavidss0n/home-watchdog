import { env } from "./env.js";

export type JobsState = "idle" | "busy" | "unknown";
export type RecoveryAction = "defer" | "wait" | "reboot" | "reset";

export type Recovery = {
  activeFails: number;
  unhealthySince: number | null;
  rebootTried: boolean;
};

export const createRecovery = (): Recovery => ({
  activeFails: 0,
  unhealthySince: null,
  rebootTried: false
});

export const markHealthy = (recovery: Recovery) => {
  recovery.activeFails = 0;
  recovery.unhealthySince = null;
  recovery.rebootTried = false;
};

const deferLimitMinutes = (jobs: JobsState): number =>
  jobs === "busy" ? env.BUSY_JOBS_MAX_DEFER_MINUTES : env.UNKNOWN_JOBS_MAX_DEFER_MINUTES;

/** What to do about one failed health check */
export const decideOnFailedCheck = (recovery: Recovery, jobs: JobsState, now: number): RecoveryAction => {

  recovery.unhealthySince ??= now;

  if (jobs !== "idle") {

    const unhealthyMinutes = (now - recovery.unhealthySince) / (60 * 1000);

    if (deferLimitMinutes(jobs) > unhealthyMinutes)
      return "defer";
  }

  recovery.activeFails++;

  if (env.FAILS_BEFORE_RESTART > recovery.activeFails)
    return "wait";

  recovery.activeFails = 0;

  if (recovery.rebootTried)
    return "reset";

  recovery.rebootTried = true;
  return "reboot";
};
