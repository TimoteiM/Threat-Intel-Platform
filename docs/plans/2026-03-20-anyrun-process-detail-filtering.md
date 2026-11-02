# AnyRun Process Detail Filtering Plan

1. Add reusable predicates in `AnyRunInteractiveEvidence.tsx` to classify processes as relevant/viewable for `view`, `group`, and `deep` modes.
2. Build mode-specific sidebar process lists from the existing process detail source, deduplicated as today.
3. Update sidebar rendering to use the active mode list and show mode-specific empty notes.
4. Reset invalid process selection on mode change when the selected process is not present in the filtered list.
5. Run frontend production build and verify the modal behavior manually in localhost.
