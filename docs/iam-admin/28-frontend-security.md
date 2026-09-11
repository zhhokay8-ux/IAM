# Phase 10：Frontend security

- Access Token / Refresh Token / Client Secret **不写入** LocalStorage、SessionStorage、IndexedDB、持久 Cookie。
- Admin 会话继续用现有 HttpOnly SSO Cookie（BFF 登录）；前端只带 Cookie + CSRF。
- Axios 对 introspect / revoke / rotate-secret 不把 token/secret 打到 `console`。
- Secret 对话框必须勾选「我已经安全保存 Secret」。
- Signing Key 页只渲染 kid/algorithm/status/created/expires/kms_key_id。
- Config 页只读，文案标明 READ_ONLY / RESTART_REQUIRED。
- 隐藏无权限按钮 ≠ 安全；写操作仍要 `admin.*.write` / `rotate` / `revoke`。
