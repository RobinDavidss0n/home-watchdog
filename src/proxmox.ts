import { env, getProxmoxAuthHeader } from "./env.js";
import { logger } from "./logger.js";

const module = "Proxmox";

const sendVmCommand = async (command: "reboot" | "reset"): Promise<boolean> => {
  logger.info(module, `Triggering ${command} for VM ${env.HA_VM_ID} on node ${env.PROXMOX_NODE}`);

  try {
    const response = await fetch(
      `${env.PROXMOX_HOST}/api2/json/nodes/${env.PROXMOX_NODE}/qemu/${env.HA_VM_ID}/status/${command}`,
      {
        method: "POST",
        headers: {
          "Authorization": getProxmoxAuthHeader()
        }
      }
    );

    if (!response.ok) {
      throw new Error(`Proxmox API responded with status: ${response.status}`);
    }

    logger.info(module, `${command} command sent successfully to Proxmox API`);
    return true;

  } catch (error) {
    logger.error(module, `Failed to execute VM ${command}`, error instanceof Error ? error.message : error);
    return false;
  }
};

/** Clean ACPI reboot, kind to HA's database */
export const rebootHaVm = (): Promise<boolean> => sendVmCommand("reboot");

/** Power cut, for when a reboot didn't help */
export const resetHaVm = (): Promise<boolean> => sendVmCommand("reset");
