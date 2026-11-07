import { useCallback, useEffect, useState } from "react";
import { Events } from "@wailsio/runtime";
import { Preferences } from "@bindings/services";
import type { UIPreferences } from "@bindings/preferences/models.js";

const EVENT_PREFERENCES_CHANGED = "netbird:preferences:changed";

// useStartupProfiles holds the profiles the GUI connects when it starts on a
// daemon with concurrent profiles. The list lives in the UI preferences of the
// OS user, so it follows the user rather than the daemon.
export const useStartupProfiles = () => {
    const [startup, setStartup] = useState<Set<string>>(new Set());

    useEffect(() => {
        let cancelled = false;
        Preferences.Get()
            .then((prefs) => {
                if (!cancelled) setStartup(new Set(prefs?.startupProfiles ?? []));
            })
            .catch((err: unknown) => {
                console.warn("[useStartupProfiles] load preferences failed", err);
            });
        const off = Events.On(EVENT_PREFERENCES_CHANGED, (e: { data?: UIPreferences }) => {
            if (e.data) setStartup(new Set(e.data.startupProfiles ?? []));
        });
        return () => {
            cancelled = true;
            off();
        };
    }, []);

    const setStartupProfile = useCallback(async (profileId: string, enabled: boolean) => {
        try {
            await Preferences.SetStartupProfile({ profileId, enabled });
        } catch (err: unknown) {
            console.error("[useStartupProfiles] SetStartupProfile failed", err);
        }
    }, []);

    return { startup, setStartupProfile };
};
