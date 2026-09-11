import { defineStore } from "pinia";
import { ref } from "vue";

/** Introspection / presented token lives only in memory. Never persist. */
export const useTokenMemoryStore = defineStore("tokenMemory", () => {
  const presentedToken = ref("");
  const result = ref<unknown>(null);

  function setPresented(token: string): void {
    presentedToken.value = token;
  }

  function setResult(value: unknown): void {
    result.value = value;
  }

  function clear(): void {
    presentedToken.value = "";
    result.value = null;
  }

  return { presentedToken, result, setPresented, setResult, clear };
});
