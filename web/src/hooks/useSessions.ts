import { useCallback, useEffect, useRef, useState } from "react";
import type { SessionResponse } from "../lib/types";
import { fetchSessions, type SessionsEnvelope } from "../lib/api";
import { setServerDown } from "../lib/connectionState";
import { beginRead, markReadApplied, startedReads } from "../lib/sessionReads";

const POLL_INTERVAL = 3000;
const LOCAL_ORDERING_WINDOW_MS = 4000;

export function useSessions() {
  const [sessions, setSessions] = useState<SessionResponse[]>([]);
  const [workspaceOrdering, setWorkspaceOrdering] = useState<string[]>([]);
  const [error, setError] = useState(false);
  const [loaded, setLoaded] = useState(false);
  const [appliedRead, setAppliedRead] = useState(0);
  const lastReadRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const lastLocalOrderingAtRef = useRef<number>(0);
  // Pushed statuses by id, with the newest read begun at push time; reads at or below it predate the push.
  const pushedRef = useRef(new Map<string, { status: SessionResponse["status"]; read: number }>());

  const injectSession = useCallback((session: SessionResponse) => {
    // Single-session responses omit rate-limit fields; keep the last known values (#3514).
    setSessions((prev) => {
      if (prev.some((s) => s.id === session.id)) return prev;
      return [session, ...prev];
    });
  }, []);

  const markLocalOrderingUpdate = useCallback(() => {
    lastLocalOrderingAtRef.current = Date.now();
  }, []);

  const applyResult = useCallback((data: SessionsEnvelope | null, read: number) => {
    if (data !== null) {
      if (read < lastReadRef.current) return;
      lastReadRef.current = read;
      const pushed = pushedRef.current;
      setSessions(
        data.sessions.map((s) => {
          const p = pushed.get(s.id);
          if (!p) return s;
          if (read > p.read) {
            pushed.delete(s.id);
            return s;
          }
          return { ...s, status: p.status };
        }),
      );
      setAppliedRead(read);
      // Ignore server ordering while a local drag's PUT may still be landing.
      if (Date.now() - lastLocalOrderingAtRef.current > LOCAL_ORDERING_WINDOW_MS) {
        setWorkspaceOrdering(data.workspace_ordering);
      }
      setError(false);
      setServerDown(false);
    } else {
      setError(true);
      setServerDown(true);
    }
    setLoaded(true);
  }, []);

  // Published after the commit so no row sees the new ordinal beside the previous snapshot.
  useEffect(() => {
    // eslint-disable-next-line react-you-might-not-need-an-effect/no-event-handler
    if (appliedRead) markReadApplied(appliedRead);
  }, [appliedRead]);

  const refresh = useCallback(() => {
    const read = beginRead();
    void fetchSessions().then((data) => applyResult(data, read));
  }, [applyResult]);

  useEffect(() => {
    refresh();
    intervalRef.current = setInterval(refresh, POLL_INTERVAL);
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [refresh]);

  const applyPushedStatus = useCallback((id: string, status: SessionResponse["status"]) => {
    pushedRef.current.set(id, { status, read: startedReads() });
    setSessions((prev) => prev.map((s) => (s.id === id ? { ...s, status } : s)));
  }, []);

  const setSessionStatus = useCallback((id: string, status: SessionResponse["status"]) => {
    setSessions((prev) => prev.map((s) => (s.id === id ? { ...s, status } : s)));
  }, []);

  const applySession = useCallback((session: SessionResponse) => {
    setSessions((prev) =>
      prev.map((s) =>
        s.id === session.id
          ? {
              ...session,
              rate_limit: session.rate_limit === undefined ? s.rate_limit : session.rate_limit,
              rate_limit_auto_resume: session.rate_limit_auto_resume ?? s.rate_limit_auto_resume,
            }
          : s,
      ),
    );
  }, []);

  return {
    sessions,
    workspaceOrdering,
    setWorkspaceOrdering,
    markLocalOrderingUpdate,
    error,
    loaded,
    injectSession,
    setSessionStatus,
    applySession,
    refresh,
    applyPushedStatus,
  };
}
