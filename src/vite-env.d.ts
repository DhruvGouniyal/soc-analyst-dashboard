/// <reference types="vite/client" />

interface ImportMetaEnv {
  /**
   * Base URL of the SOC backend / detection engine, e.g.
   * `http://192.168.56.105:8000`. When unset the dashboard runs on mock data.
   */
  readonly VITE_SOC_API_URL?: string;
}

interface ImportMeta {
  readonly env: ImportMetaEnv;
}
