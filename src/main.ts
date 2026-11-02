import { Browser, BrowserContext, chromium, Page } from "playwright";
import { env } from "./env.js";
import { logger } from "./logger.js";
import { rebootHaVm, resetHaVm } from "./proxmox.js";
import { getJobsState } from "./ha-jobs.js";
import { createRecovery, decideOnFailedCheck, markHealthy } from "./recovery.js";
import dayjs from "dayjs";
import { sendHaNotification } from "./ha-notifications.js";

const module = "Main";

async function run() {

  const recovery = createRecovery();
  let isUnhealthy = false;
  let justRestarted: "reboot" | "reset" | null = null;
  let simulatedFails = env.SIMULATE_UI_FAILS;
  let lastHeartbeat = Date.now();
  
  while (true) {

    let browser: Browser;
    let context: BrowserContext;
    let page: Page;

    const cleanup = async (includeBrowser: boolean) => {

      await page   ?.close().catch(() => {});
      await context?.close().catch(() => {});

      if (includeBrowser)
        await browser?.close().catch(() => {});
    }
  
    try {
      
      logger.debug(module, "(Re)initializing Playwright");      
      
      browser = await chromium.launch({ headless: true });
      context = await browser.newContext({ ignoreHTTPSErrors: true });
      page    = await context.newPage();
    
      let loops = 0;
    
      while (env.REINIT_BROWSER_LOOPS > loops) {
    
        loops++;
        
        try {

          if (simulatedFails > 0) {
            simulatedFails--;
            throw new Error("Simulated UI failure for testing");
          }

          await page.goto(
            `${env.HA_BASE_URL}/${env.HA_HEALTH_DASH_URL_PATH}`, 
            { 
              waitUntil: "networkidle",
              timeout: env.UI_LOAD_TIMEOUT_MS 
            }
          );
          
          await page.waitForSelector(
            `text="${env.HA_HEALTH_DASH_TEXT}"`,
            { timeout: env.UI_LOAD_TIMEOUT_MS }
          );
          
          logger.debug(module, "UI health check passed :)");

          if(isUnhealthy) {

            logger.info(module, `Healthy again :)`);
            
            isUnhealthy = false;
          }

          markHealthy(recovery);

          if (justRestarted) {
            await sendHaNotification(`HA Watchdog: Home Assistant was restarted (${justRestarted}) and has recovered successfully :)`);
            justRestarted = null;
          }

          if (Date.now() - lastHeartbeat >= env.HEARTBEAT_MINUTES * 60 * 1000) {
            logger.info(module, "Still healthy");
            lastHeartbeat = Date.now();
          }
      
        } catch (error) {

          logger.error(module, `UI health check failed :(`, error);
          
          const action = decideOnFailedCheck(recovery, await getJobsState(), Date.now());
          isUnhealthy = true;
      
          if (action === "defer") {
            logger.info(module, "Supervisor is busy or unreachable. Deferring restart.");

            await cleanup(false);
            context = await browser.newContext({ ignoreHTTPSErrors: true });
            page    = await context.newPage();

            logger.info(module, `Waiting ${env.WAIT_AFTER_JOB_DETECTED_MINUTES} minutes before rechecking...`);
            await new Promise(resolve => setTimeout(resolve, env.WAIT_AFTER_JOB_DETECTED_MINUTES * 60 * 1000));

          } else if (action === "wait") {
            
            logger.info(module, `UI health check failed, but fail count (${recovery.activeFails}) is below threshold (${env.FAILS_BEFORE_RESTART}). Deferring restart.`);
            
          } else {

            logger.info(module, `Active fails threshold reached (${env.FAILS_BEFORE_RESTART}). Next step: ${action}.`);

            const timestamp = `${dayjs().format("YYYY-MM-DD _ HH-mm-ss-SSS")}`;
            const path = `${env.FAIL_SCREENSHOT_PATH}/${timestamp}.png`;

            await page.screenshot({ path, fullPage: true }).catch(e => {
              logger.error(module, "Failed to capture screenshot of failure", e)
            });

            logger.info(module, `Saved failure screenshot to ${path}`);

            // A reboot that couldn't even be sent goes straight on to the reset
            const rebooted = action === "reboot" && await rebootHaVm();
            const reset = !rebooted && await resetHaVm();

            if (rebooted || reset) {

              justRestarted = rebooted ? "reboot" : "reset";

              logger.info(module, `Waiting ${env.WAIT_AFTER_RESTART_MINUTES} minutes for VM to restart before continuing...`);
              await new Promise(resolve => setTimeout(resolve, env.WAIT_AFTER_RESTART_MINUTES * 60 * 1000));

              break; // Exit loop after triggering restart, reinitializing browser
            }

            await sendHaNotification("HA Watchdog: Home Assistant is unhealthy and could not be restarted :(");
          }
          
        }

        if(env.DEMO_RUN)
          break;
    
        await new Promise(resolve => setTimeout(resolve, env.CHECK_INTERVAL_MS));
      }
      
      await cleanup(true);
  
    } catch (error) {
      logger.error(module, "Unexpected error in watchdog main loop", error);
  
      await cleanup(true);
    }

    if(env.DEMO_RUN) {
      logger.debug(module, "Demo run done")
      // Wait indefinitely to allow inspection of container
      await new Promise(resolve => setTimeout(resolve, 999999999));
      break;
    }
  }

};

logger.info(module, "-- Watchdog service started --");
run();