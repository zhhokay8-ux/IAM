import { defineStore } from "pinia";
import { computed, ref } from "vue";
import { adminApi } from "../api/admin";
import { ApiError } from "../api/errors";
import type { Me } from "../api/types";
import { can } from "../permissions";

export const useAuthStore = defineStore("auth", () => {
  const me = ref<Me | null>(null);
  const loaded = ref(false);

  const permissions = computed(() => me.value?.permissions ?? []);
  const roles = computed(() => me.value?.roles ?? []);

  async function load(): Promise<boolean> {
    try {
      me.value = await adminApi.me();
      loaded.value = true;
      return true;
    } catch (error) {
      me.value = null;
      loaded.value = true;
      if (error instanceof ApiError && error.status === 401) {
        return false;
      }
      throw error;
    }
  }

  function has(code: string): boolean {
    return can(permissions.value, code);
  }

  function clear(): void {
    me.value = null;
  }

  return { me, loaded, permissions, roles, load, has, clear };
});
