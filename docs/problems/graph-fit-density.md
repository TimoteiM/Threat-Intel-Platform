# A fitted graph can still be unreadable

**Status** Open. Seen in Narrative; it is not a Timeline problem and must not
be fixed inside one layout.

`cy.fit()` scales a drawing to whichever dimension binds first. Case #71 — 22
nodes over 14 rules — lays out tall and narrow under `dagre rankDir: LR`, so
fitting scales to the height and the nodes render at thumbnail scale on a
1440×900 frame. The fit is working; the result is unreadable.

Measured by rendering the real component against the endpoint's own JSON in
headless Chromium: #1849 (3 nodes) fills the frame, #1440 (33 nodes) is
comfortable, **#71 (22 nodes) is not**, and the difference is the aspect ratio
of the layout rather than the node count.

Why it belongs on its own
-------------------------
It is a property of fit-against-layout-aspect, so it will reappear in Timeline,
in Topology, and in whatever is added next. Fixing it inside the Timeline work
would fix it for one layout and leave it in the others — the same mistake as
one implementation per emitter grouping.

What a fix has to decide
------------------------
- whether to cap how far `fit` may zoom out, and read the overflow as
  pannable rather than shrinking past legibility
- whether a tall-narrow dagre result should become multi-column before
  fitting, rather than after
- what "readable" means as a number, so this can be measured rather than
  judged by eye: a minimum rendered node height is the obvious candidate and
  has not been agreed

Fullscreen now exists, so the symptom is reviewable; it is not a reason to
leave it.
