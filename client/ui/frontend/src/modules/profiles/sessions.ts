import type { TFunction } from "i18next";
import type { SessionStatus } from "@bindings/services/models.js";
import { useStatus } from "@/contexts/StatusContext";

// useProfileSessions maps profile IDs to their sessions on a daemon with
// concurrent profiles. The daemon leaves out idle sessions that are not
// focused, so a missing entry means the profile is disconnected.
export const useProfileSessions = (): Map<string, SessionStatus> => {
    const { status } = useStatus();
    const sessions = new Map<string, SessionStatus>();
    for (const s of status?.sessions ?? []) {
        sessions.set(s.profileId, s);
    }
    return sessions;
};

export const sessionRuns = (session?: SessionStatus): boolean =>
    session?.status === "Connected" || session?.status === "Connecting";

const STATUS_KEYS: Record<string, string> = {
    Connected: "tray.status.connected",
    Connecting: "tray.status.connecting",
    NeedsLogin: "tray.status.needsLogin",
    LoginFailed: "tray.status.loginFailed",
    SessionExpired: "tray.status.sessionExpired",
};

export const sessionStatusLabel = (t: TFunction, session?: SessionStatus): string => {
    const key = session ? STATUS_KEYS[session.status] : undefined;
    return t(key ?? "tray.status.disconnected");
};
