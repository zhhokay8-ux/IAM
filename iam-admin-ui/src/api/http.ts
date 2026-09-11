import axios, { type AxiosError } from "axios";
import { ElMessage } from "element-plus";
import { parseApiError, readCookie, userMessage } from "./errors";

export const http = axios.create({
  baseURL: "/",
  withCredentials: true,
  timeout: 30000
});

http.interceptors.request.use((config) => {
  const csrf = readCookie("IAM_CSRF");
  if (csrf) {
    config.headers["X-CSRF-Token"] = csrf;
  }
  const url = config.url ?? "";
  if (url.includes("/tokens/introspect") || url.includes("/tokens/revoke") || url.includes("rotate-secret")) {
    config.headers["X-Skip-Body-Log"] = "1";
  }
  return config;
});

http.interceptors.response.use(
  (response) => response,
  (error: AxiosError) => {
    const status = error.response?.status ?? 0;
    const apiError = parseApiError(status, error.response?.data);
    if (status === 401) {
      window.dispatchEvent(new CustomEvent("iam-admin-unauthorized"));
    } else {
      ElMessage.error(userMessage(apiError));
    }
    return Promise.reject(apiError);
  }
);
