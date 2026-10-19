"use client";

import React from "react";
import { URLLexicalMLEvidence, URLMLScoreEvidence } from "@/lib/types";
import styles from "./LexicalRiskExplainer.module.css";

type FeatureCopy = { label: string; description: string; value: (value: number) => string };

const FEATURE_COPY: Record<string, FeatureCopy> = {
  url_length: { label: "URL length", description: "Long URLs can conceal misleading paths or parameters.", value: (v) => `${Math.round(v)} characters` },
  hostname_length: { label: "Hostname length", description: "Long hostnames may be used to imitate brands or obscure the real domain.", value: (v) => `${Math.round(v)} characters` },
  path_length: { label: "Path length", description: "A long path can make the destination harder to inspect at a glance.", value: (v) => `${Math.round(v)} characters` },
  query_length: { label: "Query length", description: "Large query strings can carry tracking data or obscure a destination.", value: (v) => `${Math.round(v)} characters` },
  dot_count: { label: "Dot count", description: "Many dots can indicate deeply nested or visually deceptive subdomains.", value: (v) => `${Math.round(v)} dots` },
  hyphen_count: { label: "Hyphen count", description: "Multiple hyphens are common in lookalike or campaign domains.", value: (v) => `${Math.round(v)} hyphens` },
  digit_ratio: { label: "Digit ratio", description: "A high number of digits can make a URL look generated or disposable.", value: (v) => `${Math.round(v * 100)}% of letters and digits` },
  subdomain_depth: { label: "Subdomain depth", description: "Extra subdomain levels can hide the registrable domain from users.", value: (v) => `${Math.round(v)} levels` },
  has_ip_host: { label: "IP address as host", description: "Direct IP links avoid a normal domain name and are uncommon in legitimate user-facing links.", value: (v) => v ? "Detected" : "Not detected" },
  has_at_symbol: { label: "@ symbol", description: "An @ symbol can make the visible beginning of a URL misleading.", value: (v) => v ? "Detected" : "Not detected" },
  has_punycode: { label: "Punycode hostname", description: "Punycode can represent international text but is also used for visual lookalikes.", value: (v) => v ? "Detected" : "Not detected" },
  has_sensitive_keyword: { label: "Sensitive wording", description: "Words such as login, verify, payment, or password are common in credential lures.", value: (v) => v ? "Detected" : "Not detected" },
  has_suspicious_tld: { label: "Higher-risk TLD", description: "The top-level domain appears more often in short-lived abuse, but is not malicious by itself.", value: (v) => v ? "Detected" : "Not detected" },
  query_param_count: { label: "Query parameters", description: "Numerous parameters can obscure what a link does or where it came from.", value: (v) => `${Math.round(v)} parameters` },
  path_depth: { label: "Path depth", description: "Deep paths can make a URL harder to read and validate.", value: (v) => `${Math.round(v)} levels` },
  entropy: { label: "Character randomness", description: "Higher entropy means the URL looks less human-readable and more machine-generated.", value: (v) => `${v.toFixed(2)} entropy` },
  is_shortener: { label: "URL shortener", description: "Shorteners hide the final destination until the link is followed.", value: (v) => v ? "Detected" : "Not detected" },
  uses_https: { label: "HTTPS", description: "Encryption protects the connection, but does not prove the site itself is trustworthy.", value: (v) => v ? "Used" : "Not used" },
  has_abnormal_port: { label: "Unusual network port", description: "A non-standard web port is less common for normal public websites.", value: (v) => v ? "Detected" : "Not detected" },
  brand_keyword_count: { label: "Brand wording", description: "Brand terms outside the legitimate root domain can indicate impersonation.", value: (v) => `${Math.round(v)} matches` },
};

function clamp(value: number, min = 0, max = 1) {
  return Math.min(max, Math.max(min, value));
}

// `scoreTone` is gone with the probability it coloured.
//
// It mapped a number to Low / Medium / High with a traffic-light colour, which
// is the single thing that made a shape heuristic read as a verdict. Measured
// against the only external labels available, that number ranked flagged URLs
// below clean ones; on our own corpus it called 1,008 of 1,535 URLs high.
// docs/design/lexical-scoring-retirement.md.

export default function LexicalRiskExplainer({ lexical, normalized }: {
  lexical: URLLexicalMLEvidence;
  normalized?: URLMLScoreEvidence;
}) {
  // The assessment did not run.
  //
  // The backend's exception path emits `enabled: false` with `score: 0.0`,
  // and 0.0 is a legitimate score meaning "nothing suspicious about this
  // URL's shape" — so without this guard a crash drew a green ring reading
  // "0% lexical risk / Low". Same defect as the `error: null` that was
  // propagated for a skipped model, with a crash as the trigger instead.
  //
  // `=== false` rather than falsy: a payload from before the backend set
  // this field has `enabled` undefined, and treating that as disabled would
  // blank the panel on every historical report.
  if (lexical?.enabled === false) {
    return (
      <div className={styles.explainer}>
        <div className={styles.hero}>
          <div className={styles.heroCopy}>
            <div className={styles.eyebrow}>URL structure assessment</div>
            <div className={styles.titleLine}><h4>Not assessed</h4><span>no score</span></div>
            <p><strong>This URL was not scored.</strong> No lexical risk value is
              available, which is different from a low one.</p>
            <div className={styles.boundary}>
              <span>Reason</span> {lexical?.error || "The assessment did not complete and recorded no reason."}
            </div>
          </div>
        </div>
      </div>
    );
  }

  const observations = lexical?.observations || [];
  const features = lexical?.features || {};
  const contributions = lexical?.feature_contributions || {};
  const topNames = (lexical?.top_features || []).slice(0, 5);
  const maxImpact = Math.max(0.001, ...topNames.map((name) => Math.abs(Number(contributions[name] || 0))));

  return (
    <div className={styles.explainer}>
      <div className={styles.hero}>
        <div className={styles.heroCopy}>
          <div className={styles.eyebrow}>URL structure</div>
          <div className={styles.titleLine}>
            <h4>{observations.length ? `${observations.length} observation${observations.length === 1 ? "" : "s"}` : "Nothing notable"}</h4>
            <span>no score</span>
          </div>
          <p>
            <strong>
              {observations.length
                ? "Each statement below is a fact about how this URL is written, checkable against the link itself."
                : "Nothing about how this URL is written stood out."}
            </strong>{" "}
            This describes the URL text only — its hostname, path, characters and keywords.
          </p>
          <div className={styles.boundary}>
            <span>Important</span> It does not inspect page content, ownership, reputation,
            redirects or sandbox behaviour, so it cannot determine a verdict by itself.
            These observations are evidence for one, not one themselves.
          </div>
        </div>
      </div>

      {observations.length > 0 && (
        <div className={styles.features}>
          {observations.map((observation) => (
            <div className={styles.feature} key={observation.code}>
              <div className={styles.featureTop}>
                <div><strong>{observation.code.replaceAll("_", " ")}</strong></div>
              </div>
              <p>{observation.statement}</p>
            </div>
          ))}
        </div>
      )}

      <div className={styles.featuresHeader}>
        <div>
          <strong>Measured values behind these observations</strong>
          <span>The numbers the statements above were derived from, for anyone checking them.</span>
        </div>
        <span>{topNames.length} shown</span>
      </div>
      {topNames.length ? (
        <div className={styles.features}>
          {topNames.map((name) => {
            const copy = FEATURE_COPY[name] || { label: name.replaceAll("_", " "), description: "A structural value measured from the URL.", value: (v: number) => String(v) };
            const value = Number(features[name] ?? 0);
            const impact = Number(contributions[name] ?? 0);
            return (
              <div className={styles.feature} key={name}>
                <div className={styles.featureTop}>
                  <div><strong>{copy.label}</strong><span>{copy.value(value)}</span></div>
                </div>
                <p>{copy.description}</p>
                <div className={styles.impactTrack}><span className={impact < 0 ? styles.protectiveBar : styles.riskyBar} style={{ width: `${Math.max(8, Math.abs(impact) / maxImpact * 100)}%` }} /></div>
                <div className={styles.impactLabel}>Relative magnitude among the values shown</div>
              </div>
            );
          })}
        </div>
      ) : <div className={styles.noFeatures}>No measured values were recorded for this URL.</div>}

      {lexical?.error && (
        <div className={styles.technicalNote}>
          <span>Note: {lexical.error}</span>
        </div>
      )}
    </div>
  );
}
