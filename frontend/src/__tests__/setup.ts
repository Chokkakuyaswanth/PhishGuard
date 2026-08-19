import '@testing-library/jest-dom/vitest'

// Recharts' ResponsiveContainer observes its box; jsdom ships no ResizeObserver,
// and without this every chart render throws before assertions run.
class ResizeObserverStub {
  observe() {}
  unobserve() {}
  disconnect() {}
}

globalThis.ResizeObserver = globalThis.ResizeObserver ?? (ResizeObserverStub as never)

// ResponsiveContainer measures its parent, which jsdom always reports as 0x0.
for (const prop of ['offsetWidth', 'offsetHeight'] as const) {
  Object.defineProperty(HTMLElement.prototype, prop, { configurable: true, value: 600 })
}
