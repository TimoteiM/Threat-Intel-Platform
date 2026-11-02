"use client";

/**
 * A 2px bar across the top of the content column while a navigation is in
 * flight.
 *
 * App Router gives no navigation-start event, so this watches the thing that
 * actually precedes one: a click on a same-document link. The bar creeps
 * toward 90% on an easing curve — never reaching it, because we do not know
 * how long the next page takes — and completes when `usePathname` changes.
 *
 * Deliberately not a full-screen curtain. Pages here mount and then fetch, so
 * a curtain would hide markup that is already painted and make navigation feel
 * slower than it is.
 */

import React, { useEffect, useRef, useState } from "react";
import { usePathname } from "next/navigation";

export default function RouteProgress() {
  const pathname = usePathname();
  const [progress, setProgress] = useState(0);
  const [visible, setVisible] = useState(false);
  const timer = useRef<ReturnType<typeof setInterval> | null>(null);
  const settled = useRef<ReturnType<typeof setTimeout> | null>(null);

  const stop = () => {
    if (timer.current) {
      clearInterval(timer.current);
      timer.current = null;
    }
  };

  useEffect(() => {
    const onClick = (event: MouseEvent) => {
      // Modified clicks open elsewhere; they are not this document navigating.
      if (event.defaultPrevented || event.button !== 0) return;
      if (event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;

      const anchor = (event.target as HTMLElement | null)?.closest?.("a");
      if (!anchor) return;

      const href = anchor.getAttribute("href");
      if (!href || href.startsWith("#")) return;
      if (anchor.target && anchor.target !== "_self") return;
      if (anchor.hasAttribute("download")) return;

      let destination: URL;
      try {
        destination = new URL(anchor.href, window.location.href);
      } catch {
        return;
      }
      if (destination.origin !== window.location.origin) return;
      if (destination.pathname === window.location.pathname) return;

      if (settled.current) clearTimeout(settled.current);
      stop();
      setVisible(true);
      setProgress(8);
      timer.current = setInterval(() => {
        // Ease toward 90 and stall there: the remaining 10% belongs to the
        // page actually arriving, and faking it past that is a lie.
        setProgress((current) => (current >= 90 ? current : current + (90 - current) * 0.08));
      }, 120);
    };

    document.addEventListener("click", onClick, true);
    return () => {
      document.removeEventListener("click", onClick, true);
      stop();
    };
  }, []);

  // The route changed, so the navigation finished: fill, then fade out.
  useEffect(() => {
    stop();
    if (!visible) return;
    setProgress(100);
    settled.current = setTimeout(() => {
      setVisible(false);
      setProgress(0);
    }, 260);
    return () => {
      if (settled.current) clearTimeout(settled.current);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [pathname]);

  if (!visible) return null;

  return (
    <div className="route-progress" aria-hidden="true">
      <span className="route-progress__bar" style={{ width: `${progress}%` }} />
    </div>
  );
}
