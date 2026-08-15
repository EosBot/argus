"use client";

import { useCallback, useEffect, useState } from "react";
import { AnimatePresence, motion } from "motion/react";
import {
  useNotifications,
  type NotificationItem,
  type NotificationSeverity,
} from "../../hooks/useNotifications";
import Toast from "./Toast";

interface ToastInstance {
  id: string;
  title: string;
  body: string | null;
  severity: NotificationSeverity;
}

export default function ToastContainer() {
  const [toasts, setToasts] = useState<ToastInstance[]>([]);

  const handleNotification = useCallback((n: NotificationItem) => {
    const toast: ToastInstance = {
      id: n.id,
      title: n.title,
      body: n.body,
      severity: n.severity,
    };
    setToasts((prev) => [toast, ...prev].slice(0, 5));
  }, []);

  // Connect to WebSocket notifications
  useNotifications(undefined, handleNotification);

  const dismiss = useCallback((id: string) => {
    setToasts((prev) => prev.filter((t) => t.id !== id));
  }, []);

  return (
    <div
      aria-live="polite"
      aria-label="Notifications"
      style={{
        position: "fixed",
        bottom: 16,
        right: 16,
        zIndex: 1200,
        display: "flex",
        flexDirection: "column",
        gap: 8,
        pointerEvents: "none",
      }}
    >
      <AnimatePresence mode="popLayout">
        {toasts.map((toast) => (
          <Toast
            key={toast.id}
            title={toast.title}
            body={toast.body}
            severity={toast.severity}
            onClose={() => dismiss(toast.id)}
          />
        ))}
      </AnimatePresence>
    </div>
  );
}
