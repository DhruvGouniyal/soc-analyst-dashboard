/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL of the SOC backend / detection engine, e.g.
   * `http://10.139.116.20:8000`. When unset the dashboard runs on mock data.
   */
  readonly VITE_SOC_API_URL?: string;

  /**
   * The monitored host's IP, e.g. `10.139.116.20`. Used to exclude the victim
   * from the "Top Attack Sources" panel. Set this to the same address as the
   * backend's `SOC_VICTIM_IP`. Falls back to the lab default when unset.
   */
  readonly VITE_SOC_VICTIM_IP?: string;

  /**
   * URL of the companion ThreatPulse-AI app, opened from the sidebar link.
   * Defaults to its dev URL (`http://localhost:3000`); set to the deployed URL
   * for a shared demo.
   */
  readonly VITE_THREATPULSE_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
