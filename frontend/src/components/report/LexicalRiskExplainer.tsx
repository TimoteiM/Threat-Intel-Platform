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

function scoreTone(score: number) {
  if (score < .3) return { label: "Low", color: "#38d9a9", summary: "The URL structure looks mostly typical." };
  if (score <= .65) return { label: "Medium", color: "#fbbf24", summary: "The URL contains structural patterns worth reviewing." };
  return { label: "High", color: "#fb7185", summary: "The URL structure resembles patterns often seen in phishing links." };
}

export default function LexicalRiskExplainer({ lexical, normalized }: {
  lexical: URLLexicalMLEvidence;
  normalized?: URLMLScoreEvidence;
}) {
  const score = clamp(
    typeof normalized?.phishing_probability === "number"
      ? normalized.phishing_probability
      : Number(lexical?.score || 0),
  );
  const tone = scoreTone(score);
  const thresholds = lexical?.thresholds || {};
  const lowMax = Number(thresholds.low_max ?? .3);
  const mediumMax = Number(thresholds.medium_max ?? .65);
  const lexicalWeight = clamp(Number(lexical?.weights?.lexical_weight ?? .25));
  const features = lexical?.features || {};
  const contributions = lexical?.feature_contributions || {};
  const topNames = (lexical?.top_features || []).slice(0, 5);
  const maxImpact = Math.max(0.001, ...topNames.map((name) => Math.abs(Number(contributions[name] || 0))));

  return (
    <div className={styles.explainer}>
      <div className={styles.hero} style={{ "--score-color": tone.color } as React.CSSProperties}>
        <div className={styles.scoreRing} style={{ "--score": `${score * 360}deg` } as React.CSSProperties}>
          <div><strong>{Math.round(score * 100)}%</strong><span>lexical risk</span></div>
        </div>
        <div className={styles.heroCopy}>
          <div className={styles.eyebrow}>URL structure assessment</div>
          <div className={styles.titleLine}><h4>{tone.label} lexical risk</h4><span>{String(lexical?.model_source || "built-in").replaceAll("_", " ")}</span></div>
          <p><strong>{tone.summary}</strong> This probability is based only on how the URL is written—its length, characters, hostname, path, and keywords.</p>
          <div className={styles.boundary}><span>Important</span> It does not inspect page content, ownership, reputation, redirects, or sandbox behavior, so it cannot determine the final verdict by itself.</div>
        </div>
      </div>

      <div className={styles.scaleCard}>
        <div className={styles.scaleHeader}>
          <div><strong>How to read {Math.round(score * 100)}%</strong><span>The marker shows where this URL falls across the model’s three bands.</span></div>
          <span className={styles.currentBand} style={{ color: tone.color }}>{tone.label}</span>
        </div>
        <div className={styles.scale}>
          <div className={styles.lowBand} style={{ width: `${lowMax * 100}%` }} />
          <div className={styles.mediumBand} style={{ width: `${(mediumMax - lowMax) * 100}%` }} />
          <div className={styles.highBand} style={{ width: `${(1 - mediumMax) * 100}%` }} />
          <div className={styles.marker} style={{ left: `${score * 100}%`, color: tone.color }}><span>{Math.round(score * 100)}%</span></div>
        </div>
        <div className={styles.legend}>
          <span><i className={styles.lowDot} /><b>Low</b> 0–{Math.round(lowMax * 100)}% · few suspicious URL patterns</span>
          <span><i className={styles.mediumDot} /><b>Medium</b> {Math.round(lowMax * 100)}–{Math.round(mediumMax * 100)}% · review with other evidence</span>
          <span><i className={styles.highDot} /><b>High</b> above {Math.round(mediumMax * 100)}% · strong structural resemblance</span>
        </div>
      </div>

      <div className={styles.contextGrid}>
        <div className={styles.contextCard}>
          <div className={styles.contextIcon}>¼</div>
          <div><strong>Contribution to final risk</strong><p>Lexical ML has a <b>{Math.round(lexicalWeight * 100)}% weight</b> in the blended calculation. At this score, its weighted contribution is about <b>{(score * lexicalWeight * 100).toFixed(1)} points</b> on a 0–100 scale before other decision rules.</p></div>
        </div>
        <div className={styles.contextCard}>
          <div className={styles.contextIcon}>◎</div>
          <div><strong>What “probability” means</strong><p>It is the model’s confidence that the URL text resembles its learned phishing patterns—not a claim that there is a {Math.round(score * 100)}% real-world chance the site is malicious.</p></div>
        </div>
      </div>

      <div className={styles.featuresHeader}>
        <div><strong>What influenced this score</strong><span>Features are ranked by model impact and translated below.</span></div>
        <span>{topNames.length} strongest signals</span>
      </div>
      {topNames.length ? (
        <div className={styles.features}>
          {topNames.map((name) => {
            const copy = FEATURE_COPY[name] || { label: name.replaceAll("_", " "), description: "A structural value used by the lexical model.", value: (v: number) => String(v) };
            const value = Number(features[name] ?? 0);
            const impact = Number(contributions[name] ?? 0);
            const direction = impact < 0 ? "lowers" : "raises";
            return (
              <div className={styles.feature} key={name}>
                <div className={styles.featureTop}>
                  <div><strong>{copy.label}</strong><span>{copy.value(value)}</span></div>
                  <span className={impact < 0 ? styles.protective : styles.risky}>{impact < 0 ? "Lowers risk" : "Raises risk"}</span>
                </div>
                <p>{copy.description}</p>
                <div className={styles.impactTrack}><span className={impact < 0 ? styles.protectiveBar : styles.riskyBar} style={{ width: `${Math.max(8, Math.abs(impact) / maxImpact * 100)}%` }} /></div>
                <div className={styles.impactLabel}>Relative influence · {direction} the lexical score</div>
              </div>
            );
          })}
        </div>
      ) : <div className={styles.noFeatures}>The model did not provide feature-level explanations for this result.</div>}

      {(lexical?.calibration_applied || lexical?.rule_floor_applied || lexical?.error) && (
        <div className={styles.technicalNote}>
          {lexical.calibration_applied && <span>Score calibration was applied.</span>}
          {lexical.rule_floor_applied && <span>A safety rule raised the minimum score.</span>}
          {lexical.error && <span>Model note: {lexical.error}</span>}
        </div>
      )}
    </div>
  );
}
