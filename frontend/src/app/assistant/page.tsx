import { Suspense } from "react";
import AssistantWorkspace from "@/components/assistant/AssistantWorkspace";

export default function AssistantPage() {
  return (
    <Suspense fallback={null}>
      <AssistantWorkspace />
    </Suspense>
  );
}
