import { ThreatReport, ScanHistoryItem, StatsSummary } from "@/types";

const GUEST_STORAGE_KEY = "xerox_guest_scans";
const MAX_GUEST_SCANS = 50;

/**
 * Checks whether localStorage is available and functional.
 */
function isLocalStorageAvailable(): boolean {
  try {
    const testKey = "__xerox_test__";
    window.localStorage.setItem(testKey, "1");
    window.localStorage.removeItem(testKey);
    return true;
  } catch {
    return false;
  }
}

/**
 * Loads all raw threat reports stored locally for guest sessions.
 */
export function getGuestReports(): ThreatReport[] {
  if (!isLocalStorageAvailable()) return [];
  try {
    const data = window.localStorage.getItem(GUEST_STORAGE_KEY);
    if (!data) return [];
    const parsed = JSON.parse(data);
    return Array.isArray(parsed) ? parsed : [];
  } catch (err) {
    console.warn("Failed to load local guest scans:", err);
    return [];
  }
}

/**
 * Saves a completed scan report into local storage for guest operators.
 * Caps at MAX_GUEST_SCANS (50) to prevent storage exhaustion.
 */
export function saveGuestScan(report: ThreatReport): void {
  if (!isLocalStorageAvailable() || !report) return;
  try {
    const existing = getGuestReports();
    // Filter out duplicate if same scan_id already exists
    const filtered = existing.filter((s) => s.scan_id !== report.scan_id);
    const updated = [report, ...filtered].slice(0, MAX_GUEST_SCANS);
    window.localStorage.setItem(GUEST_STORAGE_KEY, JSON.stringify(updated));
  } catch (err) {
    console.warn("Failed to persist guest scan locally:", err);
  }
}

/**
 * Returns formatted ScanHistoryItem list for history & dashboard views.
 */
export function getGuestHistory(): ScanHistoryItem[] {
  const reports = getGuestReports();
  return reports.map((r) => ({
    scan_id: r.scan_id,
    target_type: r.target_type,
    defanged_target: r.defanged_target,
    risk_level: r.risk_level,
    risk_score: r.risk_score,
    analyzed_at: r.analyzed_at,
    executive_summary: r.executive_summary,
  }));
}

/**
 * Retrieves a specific ThreatReport by scan_id from local guest storage.
 */
export function getGuestReport(scanId: string): ThreatReport | null {
  const reports = getGuestReports();
  return reports.find((r) => r.scan_id === scanId) || null;
}

/**
 * Computes aggregated security telemetry for guest scans.
 */
export function getGuestStats(): StatsSummary {
  const reports = getGuestReports();
  let threats_blocked = 0;
  let benign_verified = 0;
  let suspicious_flagged = 0;
  const scans_by_type: Record<string, number> = {
    URL: 0,
    MESSAGE: 0,
    SCREENSHOT: 0,
    FILE: 0,
  };

  for (const report of reports) {
    if (report.risk_level === "CRITICAL" || report.risk_level === "HIGH RISK") {
      threats_blocked++;
    } else if (report.risk_level === "SUSPICIOUS") {
      suspicious_flagged++;
    } else {
      benign_verified++;
    }

    const typeKey = report.target_type.toUpperCase();
    scans_by_type[typeKey] = (scans_by_type[typeKey] || 0) + 1;
  }

  return {
    total_scans: reports.length,
    threats_blocked,
    benign_verified,
    suspicious_flagged,
    scans_by_type,
  };
}

/**
 * Purges all local guest scan history.
 */
export function clearGuestHistory(): void {
  if (!isLocalStorageAvailable()) return;
  try {
    window.localStorage.removeItem(GUEST_STORAGE_KEY);
  } catch (err) {
    console.warn("Failed to clear local guest scans:", err);
  }
}
