"use client";

/**
 * Sends people to the sign-in page, but only once a refusal is actually coming.
 *
 * The backend runs in one of two modes. Under `monitor` it still serves
 * unauthenticated callers while the ingest integrations are moved onto API
 * keys; putting a login wall up during that window would be an outage this
 * change caused rather than prevented. So the gate asks the server which mode
 * it is in and redirects only under `enforce`.
 *
 * This is a convenience, not the control. The control is the server refusing
 * the request — removing this component exposes nothing.
 */

import React, { useEffect, useState } from "react";
import { usePathname, useRouter } from "next/navigation";
import * as api from "@/lib/api";

const OPEN_ROUTES = new Set(["/login"]);

export default function AuthGate({ children }: { children: React.ReactNode }) {
  const router = useRouter();
  const pathname = usePathname();
  const [checked, setChecked] = useState(false);
  const [blocked, setBlocked] = useState(false);

  useEffect(() => {
    let cancelled = false;

    const check = async () => {
      if (pathname && OPEN_ROUTES.has(pathname)) {
        setChecked(true);
        return;
      }
      try {
        const status = await api.getAuthStatus();
        if (cancelled) return;
        if (status.mode === "enforce" && !status.authenticated) {
          setBlocked(true);
          const next = encodeURIComponent(pathname || "/dashboard");
          router.replace(`/login?next=${next}`);
          return;
        }
      } catch {
        // The status route is public, so a failure here is the API being down
        // rather than a credential problem. Rendering the app and letting the
        // page's own error states explain is better than a login page that
        // implies the wrong fix.
      }
      if (!cancelled) setChecked(true);
    };

    check();
    return () => {
      cancelled = true;
    };
  }, [pathname, router]);

  // Nothing is rendered while a redirect is in flight, so a protected page
  // never flashes up before it is replaced.
  if (blocked || !checked) return null;
  return <>{children}</>;
}
