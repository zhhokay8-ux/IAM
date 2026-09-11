export class ApiError extends Error {
  readonly status: number;
  readonly code: string;
  readonly traceId?: string;

  constructor(status: number, code: string, message: string, traceId?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.code = code;
    this.traceId = traceId;
  }
}

export interface ApiErrorBody {
  traceId?: string;
  code?: string;
  message?: string;
}

export function parseApiError(status: number, body: unknown): ApiError {
  const payload = (body ?? {}) as ApiErrorBody;
  const code = payload.code ?? (status === 401 ? "IAM-4010" : status === 403 ? "IAM-4030" : "IAM-5000");
  const message =
    payload.message ??
    (status === 401
      ? "Unauthorized"
      : status === 403
        ? "无权限"
        : status === 409
          ? "Conflict"
          : status >= 500
            ? "系统异常"
            : "Request failed");
  return new ApiError(status, code, message, payload.traceId);
}

export function userMessage(error: ApiError): string {
  if (error.code === "IAM-4020") {
    return "用户名或密码错误";
  }
  if (error.status === 401) {
    return "未登录或会话已失效";
  }
  if (error.status === 403) {
    return `无权限 (${error.code})`;
  }
  if (error.status === 400) {
    return error.message;
  }
  if (error.status === 409) {
    return `冲突 (${error.code}): ${error.message}`;
  }
  if (error.status >= 500) {
    return `系统异常 (${error.code})`;
  }
  return error.message;
}

export function readCookie(name: string): string | undefined {
  const parts = document.cookie.split("; ");
  for (const part of parts) {
    const idx = part.indexOf("=");
    if (idx < 0) {
      continue;
    }
    if (part.slice(0, idx) === name) {
      return decodeURIComponent(part.slice(idx + 1));
    }
  }
  return undefined;
}
