"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { getAccessToken } from "../lib/auth";

export type NotificationSeverity = "info" | "low" | "medium" | "high" | "critical";

export interface NotificationItem {
  id: string;
  user_id: string | null;
  title: string;
  body: string | null;
  severity: NotificationSeverity;
  created_at: string;
}

export interface UseNotificationsState {
  /** Received notifications, newest first */
  notifications: NotificationItem[];
  /** Count of unread notifications */
  unreadCount: number;
  /** Whether the WebSocket is connected */
  isConnected: boolean;
  /** Mark a notification as read (sends to backend via callback) */
  markAsRead: (id: string) => void;
  /** Clear all notifications */
  clearAll: () => void;
}

const HEARTBEAT_INTERVAL_MS = 30_000;
const RECONNECT_DELAYS_MS = [1_000, 2_000, 5_000, 10_000];
const MAX_NOTIFICATIONS = 50;

/**
 * Connect to the notifications WebSocket, receive notifications in real-time,
 * and maintain local state with auto-reconnect and heartbeat.
 *
 * @param userId - Optional user ID to subscribe to per-user notifications.
 * @param onNotification - Optional callback fired on each new notification.
 */
export function useNotifications(
  userId?: string,
  onNotification?: (notification: NotificationItem) => void,
): UseNotificationsState {
  const [notifications, setNotifications] = useState<NotificationItem[]>([]);
  const [isConnected, setIsConnected] = useState(false);

  const wsRef = useRef<WebSocket | null>(null);
  const reconnectAttemptRef = useRef(0);
  const reconnectTimerRef = useRef<number | null>(null);
  const heartbeatTimerRef = useRef<number | null>(null);
  const closedRef = useRef(false);
  const onNotificationRef = useRef(onNotification);

  // Keep callback ref fresh without triggering reconnect
  useEffect(() => {
    onNotificationRef.current = onNotification;
  }, [onNotification]);

  const clearHeartbeat = useCallback(() => {
    if (heartbeatTimerRef.current !== null) {
      window.clearInterval(heartbeatTimerRef.current);
      heartbeatTimerRef.current = null;
    }
  }, []);

  const markAsRead = useCallback((id: string) => {
    setNotifications((prev) =>
      prev.map((n) => (n.id === id ? { ...n, read: true } : n)),
    );
  }, []);

  const clearAll = useCallback(() => {
    setNotifications([]);
  }, []);

  useEffect(() => {
    closedRef.current = false;

    const connect = () => {
      if (closedRef.current) return;

      const wsHost = process.env.NEXT_PUBLIC_WS_URL?.replace(/^wss?:\/\//, "") || "localhost:8000";
      const protocol = window.location.protocol === "https:" ? "wss:" : "ws:";
      const ws = new WebSocket(`${protocol}//${wsHost}/ws/v1/notifications?token=${encodeURIComponent(getAccessToken() ?? "")}`);
      wsRef.current = ws;

      ws.onopen = () => {
        reconnectAttemptRef.current = 0;
        setIsConnected(true);

        // Start the authenticated subscription immediately. The backend derives
        // the user from JWT and never trusts a different client-supplied ID.
        ws.send(JSON.stringify({ type: "subscribe", ...(userId ? { user_id: userId } : {}) }));

        // Start heartbeat
        heartbeatTimerRef.current = window.setInterval(() => {
          if (ws.readyState === WebSocket.OPEN) {
            ws.send(JSON.stringify({ type: "ping" }));
          }
        }, HEARTBEAT_INTERVAL_MS);
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data as string) as {
            type?: string;
            data?: Record<string, unknown>;
          };

          if (message.type === "notification" && message.data) {
            const data = message.data;
            const item: NotificationItem = {
              id: String(data.id ?? ""),
              user_id: (data.user_id as string | null) ?? null,
              title: String(data.title ?? ""),
              body: (data.body as string | null) ?? null,
              severity: (data.severity as NotificationSeverity) ?? "info",
              created_at: String(data.created_at ?? ""),
            };

            setNotifications((prev) => [item, ...prev].slice(0, MAX_NOTIFICATIONS));
            onNotificationRef.current?.(item);
          }
        } catch {
          // Ignore malformed frames.
        }
      };

      ws.onclose = () => {
        setIsConnected(false);
        clearHeartbeat();
        if (closedRef.current) return;

        const attempt = reconnectAttemptRef.current;
        const delay = RECONNECT_DELAYS_MS[Math.min(attempt, RECONNECT_DELAYS_MS.length - 1)];
        reconnectAttemptRef.current = attempt + 1;
        reconnectTimerRef.current = window.setTimeout(connect, delay);
      };

      ws.onerror = () => {
        ws.close();
      };
    };

    connect();

    return () => {
      closedRef.current = true;
      if (reconnectTimerRef.current !== null) {
        window.clearTimeout(reconnectTimerRef.current);
        reconnectTimerRef.current = null;
      }
      clearHeartbeat();
      wsRef.current?.close();
      wsRef.current = null;
    };
  }, [userId, clearHeartbeat]);

  const unreadCount = notifications.filter((n) => !(n as NotificationItem & { read?: boolean }).read).length;

  return {
    notifications,
    unreadCount,
    isConnected,
    markAsRead,
    clearAll,
  };
}

export default useNotifications;
