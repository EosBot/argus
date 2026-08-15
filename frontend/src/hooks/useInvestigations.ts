"use client";

/* ============================================================
   ARGUS 2.0 — useInvestigations Hook
   Fetches investigation tree data from the backend API.
   ============================================================ */

import { useCallback, useEffect, useState } from "react";
import { apiFetch } from "../lib/api";

/* ============================ Types ============================ */

export type NodeStatus = "active" | "pending" | "complete" | "error";

export interface IOC {
  type: "ioc";
  id: string;
  value: string;
  kind: "domain" | "ip" | "hash" | "url" | "email";
  risk: "low" | "medium" | "high";
}

export interface Evidence {
  type: "evidence";
  id: string;
  title: string;
  kind: string;
  status: NodeStatus;
}

export interface Finding {
  type: "finding";
  id: string;
  title: string;
  severity: "info" | "low" | "medium" | "high" | "critical";
  status: NodeStatus;
  iocs: IOC[];
  evidence: Evidence[];
}

export interface Target {
  type: "target";
  id: string;
  name: string;
  status: NodeStatus;
  findings: Finding[];
}

export interface Investigation {
  type: "investigation";
  id: string;
  title: string;
  status: NodeStatus;
  targets: Target[];
}

export interface UseInvestigationsResult {
  investigations: Investigation[];
  isLoading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
  createInvestigation: (data: { title: string; description?: string }) => Promise<Investigation | null>;
  updateInvestigation: (id: string, data: Partial<Investigation>) => Promise<boolean>;
  deleteInvestigation: (id: string) => Promise<boolean>;
}

/* ============================ Hook ============================ */

export function useInvestigations(): UseInvestigationsResult {
  const [investigations, setInvestigations] = useState<Investigation[]>([]);
  const [isLoading, setIsLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const fetchInvestigations = useCallback(async () => {
    try {
      setIsLoading(true);
      setError(null);

      const data = await apiFetch<{ items: any[] }>("/api/investigations");
      const mapped = data.items.map(mapInvestigation);
      setInvestigations(mapped);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Failed to fetch investigations");
    } finally {
      setIsLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchInvestigations();
  }, [fetchInvestigations]);

  const createInvestigation = useCallback(
    async (data: { title: string; description?: string }): Promise<Investigation | null> => {
      try {
        const response = await apiFetch<any>("/api/investigations", {
          method: "POST",
          body: JSON.stringify(data),
        });
        const investigation = mapInvestigation(response);
        setInvestigations((prev) => [investigation, ...prev]);
        return investigation;
      } catch (err) {
        console.error("Failed to create investigation:", err);
        return null;
      }
    },
    []
  );

  const updateInvestigation = useCallback(
    async (id: string, data: Partial<Investigation>): Promise<boolean> => {
      try {
        await apiFetch(`/api/investigations/${id}`, {
          method: "PATCH",
          body: JSON.stringify(data),
        });
        setInvestigations((prev) =>
          prev.map((inv) => (inv.id === id ? { ...inv, ...data } : inv))
        );
        return true;
      } catch (err) {
        console.error("Failed to update investigation:", err);
        return false;
      }
    },
    []
  );

  const deleteInvestigation = useCallback(
    async (id: string): Promise<boolean> => {
      try {
        await apiFetch(`/api/investigations/${id}`, { method: "DELETE" });
        setInvestigations((prev) => prev.filter((inv) => inv.id !== id));
        return true;
      } catch (err) {
        console.error("Failed to delete investigation:", err);
        return false;
      }
    },
    []
  );

  return {
    investigations,
    isLoading,
    error,
    refresh: fetchInvestigations,
    createInvestigation,
    updateInvestigation,
    deleteInvestigation,
  };
}

/* ============================ Mapping ============================ */

function mapInvestigation(data: any): Investigation {
  return {
    type: "investigation",
    id: data.id,
    title: data.title,
    status: mapStatus(data.status),
    targets: data.targets?.map(mapTarget) || [],
  };
}

function mapTarget(data: any): Target {
  return {
    type: "target",
    id: data.id,
    name: data.name,
    status: mapStatus(data.status),
    findings: data.findings?.map(mapFinding) || [],
  };
}

function mapFinding(data: any): Finding {
  return {
    type: "finding",
    id: data.id,
    title: data.title,
    severity: data.severity || "info",
    status: mapStatus(data.status),
    iocs: data.iocs?.map(mapIOC) || [],
    evidence: data.evidence?.map(mapEvidence) || [],
  };
}

function mapIOC(data: any): IOC {
  return {
    type: "ioc",
    id: data.id,
    value: data.value,
    kind: data.kind || "domain",
    risk: data.risk || "low",
  };
}

function mapEvidence(data: any): Evidence {
  return {
    type: "evidence",
    id: data.id,
    title: data.title,
    kind: data.kind || "artifact",
    status: mapStatus(data.status),
  };
}

function mapStatus(status: any): NodeStatus {
  const statusMap: Record<string, NodeStatus> = {
    active: "active",
    open: "active",
    pending: "pending",
    complete: "complete",
    closed: "complete",
    error: "error",
  };
  return statusMap[status] || "pending";
}
