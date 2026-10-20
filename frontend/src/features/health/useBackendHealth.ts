import { useState, useEffect, useCallback, useRef } from "react";
import { checkBackendHealth, BackendHealthResult } from "@/services/api";
import { getApiBaseUrl } from "@/services/apiConfig";

export type EnclaveStatus = "online" | "degraded" | "offline" | "checking";

export interface EnclaveHealthState {
  status: EnclaveStatus;
  latencyMs: number | null;
  lastChecked: Date | null;
  errorDetail: string | null;
  version: string | null;
  databaseStatus: string | null;
  cacheStatus: string | null;
  baseUrl: string;
  recheck: () => Promise<void>;
}

export function useBackendHealth(pollIntervalMs: number = 30000): EnclaveHealthState {
  const [status, setStatus] = useState<EnclaveStatus>("checking");
  const [latencyMs, setLatencyMs] = useState<number | null>(null);
  const [lastChecked, setLastChecked] = useState<Date | null>(null);
  const [errorDetail, setErrorDetail] = useState<string | null>(null);
  const [version, setVersion] = useState<string | null>(null);
  const [databaseStatus, setDatabaseStatus] = useState<string | null>(null);
  const [cacheStatus, setCacheStatus] = useState<string | null>(null);
  const [baseUrl, setBaseUrl] = useState<string>(getApiBaseUrl());

  const activeCheckRef = useRef(false);

  const performCheck = useCallback(async () => {
    if (activeCheckRef.current) return;
    activeCheckRef.current = true;
    const currentBase = getApiBaseUrl();
    setBaseUrl(currentBase);

    try {
      const result: BackendHealthResult = await checkBackendHealth();
      setLatencyMs(result.latencyMs);
      setVersion(result.version);
      setDatabaseStatus(result.database || null);
      setCacheStatus(result.cache || null);
      setErrorDetail(null);
      setLastChecked(new Date());

      if (result.status === "healthy") {
        setStatus("online");
      } else {
        setStatus("degraded");
      }
    } catch (err: any) {
      setLatencyMs(null);
      setLastChecked(new Date());
      setStatus("offline");
      setErrorDetail(err?.userMessage || err?.message || "Security enclave connection failed");
    } finally {
      activeCheckRef.current = false;
    }
  }, []);

  useEffect(() => {
    performCheck();
    if (pollIntervalMs > 0) {
      const interval = setInterval(performCheck, pollIntervalMs);
      return () => clearInterval(interval);
    }
  }, [performCheck, pollIntervalMs]);

  return {
    status,
    latencyMs,
    lastChecked,
    errorDetail,
    version,
    databaseStatus,
    cacheStatus,
    baseUrl,
    recheck: performCheck,
  };
}
