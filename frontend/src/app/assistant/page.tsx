import { Suspense } from "react";
import AssistantWorkspace from "@/components/assistant/AssistantWorkspace";

export default function AssistantPage() {
  return (
    <main style={{ width: "100%", paddingInline: "clamp(16px, 2.5vw, 32px)" }}>
      <Suspense fallback={null}>
        <AssistantWorkspace />
      </Suspense>
    </main>
  );
}
