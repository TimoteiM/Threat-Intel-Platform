/**
 * Cytoscape needs measurement APIs jsdom does not implement. Stubbed to the
 * smallest shape the component reads, and deliberately not to something that
 * pretends to lay out: a test that believed these numbers would be asserting
 * the stub.
 */
Object.defineProperty(HTMLElement.prototype, "getBoundingClientRect", {
  configurable: true,
  value: () => ({
    width: 1024, height: 768, top: 0, left: 0, right: 1024, bottom: 768,
    x: 0, y: 0, toJSON: () => ({}),
  }),
});

if (!window.matchMedia) {
  Object.defineProperty(window, "matchMedia", {
    writable: true,
    value: (query: string) => ({
      matches: false, media: query, onchange: null,
      addEventListener: () => {}, removeEventListener: () => {},
      addListener: () => {}, removeListener: () => {},
      dispatchEvent: () => false,
    }),
  });
}
