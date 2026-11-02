"use client";

import React, { useEffect, useRef, useState } from "react";
import * as api from "@/lib/api";
import styles from "./InvestigationCaseChat.module.css";

type ChatMessage = {
  id: string;
  role: "user" | "assistant";
  content: string;
  confidence?: "high" | "medium" | "low" | null;
  limitations?: string[];
  suggested_followups?: string[];
  model?: string | null;
  created_at?: string | null;
};

const STARTERS = [
  "What evidence most strongly supports the verdict?",
  "What should the SOC do first?",
  "Which findings could be false positives?",
];

function RobotAvatar({ thinking = false }: { thinking?: boolean }) {
  return (
    <div className={`${styles.avatar} ${thinking ? styles.avatarThinking : ""}`} aria-hidden="true">
      <svg viewBox="0 0 48 48" role="img">
        <path d="M24 9V5m0 0 2.5-2.5M24 5l-2.5-2.5" />
        <rect x="9" y="11" width="30" height="25" rx="10" />
        <path d="M9 24H5v7h4m30-7h4v7h-4M16 38v4m16-4v4" />
        <circle cx="18" cy="23" r="2.5" className={styles.robotEye} />
        <circle cx="30" cy="23" r="2.5" className={styles.robotEye} />
        <path d="M18 30c3.7 2.6 8.3 2.6 12 0" />
      </svg>
      <span className={styles.onlineDot} />
    </div>
  );
}

function SendIcon() {
  return <svg viewBox="0 0 24 24" aria-hidden="true"><path d="m4 4 17 8-17 8 3-8-3-8Zm3 8h14" /></svg>;
}

export default function InvestigationCaseChat({ investigationId }: { investigationId: string }) {
  const [messages, setMessages] = useState<ChatMessage[]>([]);
  const [question, setQuestion] = useState("");
  const [asking, setAsking] = useState(false);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [clearing, setClearing] = useState(false);
  const scrollRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLTextAreaElement>(null);

  useEffect(() => {
    let active = true;
    setLoading(true);
    api.getCaseStoryChat(investigationId)
      .then((result) => active && setMessages(result?.messages || []))
      .catch((err: any) => active && setError(err?.message || "Conversation history is unavailable."))
      .finally(() => active && setLoading(false));
    return () => { active = false; };
  }, [investigationId]);

  useEffect(() => {
    scrollRef.current?.scrollTo({ top: scrollRef.current.scrollHeight, behavior: "smooth" });
  }, [messages, asking]);

  function choosePrompt(prompt: string) {
    setQuestion(prompt);
    requestAnimationFrame(() => inputRef.current?.focus());
  }

  async function ask() {
    const text = question.trim();
    if (!text || asking) return;
    const optimistic: ChatMessage = {
      id: `pending-${Date.now()}`,
      role: "user",
      content: text,
      created_at: new Date().toISOString(),
    };
    setQuestion("");
    setError("");
    setMessages((current) => [...current, optimistic]);
    setAsking(true);
    try {
      const result = await api.askCaseStory(investigationId, text);
      setMessages((current) => [
        ...current.filter((message) => message.id !== optimistic.id),
        ...(result?.messages || []),
      ]);
    } catch (err: any) {
      setMessages((current) => current.filter((message) => message.id !== optimistic.id));
      setQuestion(text);
      setError(err?.message || "I couldn’t analyze that question. Please try again.");
    } finally {
      setAsking(false);
      inputRef.current?.focus();
    }
  }

  async function clearConversation() {
    if (!messages.length || clearing || !window.confirm("Clear this investigation’s chat history?")) return;
    setClearing(true);
    setError("");
    try {
      await api.clearCaseStoryChat(investigationId);
      setMessages([]);
    } catch (err: any) {
      setError(err?.message || "The conversation could not be cleared.");
    } finally {
      setClearing(false);
    }
  }

  return (
    <section className={styles.shell} aria-label="Chat with this investigation">
      <header className={styles.header}>
        <div className={styles.identity}>
          <RobotAvatar thinking={asking} />
          <div>
            <div className={styles.titleRow}>
              <h3>Threat Analyzer - Assistant</h3>
              <span className={styles.groundedBadge}>Evidence grounded</span>
            </div>
            <p>{asking ? "Reviewing the investigation…" : "Online · Knows this case and remembers this conversation"}</p>
          </div>
        </div>
        {messages.length > 0 && (
          <button className={styles.clearButton} onClick={clearConversation} disabled={clearing || asking}>
            {clearing ? "Clearing…" : "Clear chat"}
          </button>
        )}
      </header>

      <div className={styles.conversation} ref={scrollRef} aria-live="polite">
        {!loading && messages.length === 0 && (
          <div className={styles.welcome}>
            <RobotAvatar />
            <div>
              <span className={styles.sparkle}>✦</span>
              <h4>Ask me about this investigation</h4>
              <p>I can explain the verdict, weigh conflicting signals, trace evidence, and turn findings into next actions.</p>
            </div>
          </div>
        )}
        {loading && <div className={styles.historyLoading}><span /><span /><span /> Loading conversation</div>}
        {messages.map((message, index) => (
          <div
            className={`${styles.messageRow} ${message.role === "user" ? styles.userRow : styles.assistantRow}`}
            key={message.id}
            style={{ animationDelay: `${Math.min(index, 4) * 45}ms` }}
          >
            {message.role === "assistant" && <RobotAvatar />}
            <div className={`${styles.bubble} ${message.role === "user" ? styles.userBubble : styles.assistantBubble}`}>
              <div className={styles.messageText}>{message.content}</div>
              {message.role === "assistant" && (
                <div className={styles.meta}>
                  {message.confidence && <span className={`${styles.confidence} ${styles[message.confidence]}`}>{message.confidence} confidence</span>}
                  {message.model && <span>{message.model}</span>}
                </div>
              )}
              {!!message.limitations?.length && (
                <div className={styles.limitations}>Limitations: {message.limitations.join(" · ")}</div>
              )}
              {!!message.suggested_followups?.length && message === messages[messages.length - 1] && (
                <div className={styles.followups}>
                  {message.suggested_followups.slice(0, 3).map((prompt) => (
                    <button key={prompt} onClick={() => choosePrompt(prompt)}>{prompt}</button>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
        {asking && (
          <div className={`${styles.messageRow} ${styles.assistantRow} ${styles.thinkingRow}`}>
            <RobotAvatar thinking />
            <div className={`${styles.bubble} ${styles.assistantBubble} ${styles.thinkingBubble}`}>
              <span /><span /><span /><em>Connecting the evidence</em>
            </div>
          </div>
        )}
      </div>

      {messages.length === 0 && !loading && (
        <div className={styles.starters}>
          {STARTERS.map((prompt) => <button key={prompt} onClick={() => choosePrompt(prompt)}>{prompt}</button>)}
        </div>
      )}

      {error && <div className={styles.error} role="alert">{error}</div>}
      <div className={styles.composer}>
        <textarea
          ref={inputRef}
          value={question}
          rows={1}
          maxLength={2000}
          onChange={(event) => setQuestion(event.target.value)}
          onKeyDown={(event) => {
            if (event.key === "Enter" && !event.shiftKey) {
              event.preventDefault();
              ask();
            }
          }}
          placeholder="Ask a follow-up about this case…"
          disabled={asking || loading}
          aria-label="Question about this investigation"
        />
        <button className={styles.sendButton} onClick={ask} disabled={!question.trim() || asking || loading} aria-label="Send question">
          <SendIcon />
        </button>
      </div>
      <div className={styles.footerNote}>Answers are limited to evidence stored in this investigation · Shift + Enter for a new line</div>
    </section>
  );
}
