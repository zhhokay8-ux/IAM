# Phase 4：Token Exchange Policy

**没有**独立 `TokenExchangePolicy` 表，也禁止新建。

Token Exchange 策略就是 `iam_cli_res_perm` 中 `grant_type=TOKEN_EXCHANGE` 的权限行，由现有 `TokenExchangePolicyServiceImpl.requireExchangePermission` → `IamPolicyEvaluator.validateTokenExchangePermission` 执行。

Admin 对 Permission Matrix 的 enable/disable 即改 Exchange 策略。文档与 API 见 `12-permission-matrix.md`。
