import { createPinia, setActivePinia } from "pinia";
import { describe, expect, it } from "vitest";
import { useTokenMemoryStore } from "../stores/tokenMemory";

describe("token memory", () => {
  it("clears presented token from memory", () => {
    setActivePinia(createPinia());
    const store = useTokenMemoryStore();
    store.setPresented("eyJsecret");
    store.setResult({ active: true });
    store.clear();
    expect(store.presentedToken).toBe("");
    expect(store.result).toBeNull();
  });
});
