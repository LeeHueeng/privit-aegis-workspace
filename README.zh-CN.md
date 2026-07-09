# Privit Aegis Workspace

[English](./README.md) · [한국어](./README.ko.md) · [日本語](./README.ja.md) · [中文](./README.zh-CN.md) · [GitHub Pages](https://leehueeng.github.io/privit-aegis-workspace/)

Privit Aegis Workspace 是面向 Privit Web 应用的授权安全测试工作区。它将
Aegis CLI、本地 Web 控制台、被动站点发现、安全报告、多语言文档、AI 辅助
修复提示以及 AIGate 推送质量门禁放在同一个仓库中。

## 值得关注的亮点

- Web 控制台和 CLI 共用同一套授权范围与安全基线。
- 提供韩语、英语、日语、中文 README 和指南。
- 报告会说明执行了哪些检查、通过标准是什么、保留了哪些脱敏证据。
- AI 不负责判定扫描结果，只用于配置、就绪检查和修复提示辅助。
- GitHub Actions 使用最小权限，并固定 Action 引用。

## 快速开始

```sh
npm run setup
npm run web
```

打开 `http://127.0.0.1:4317` 即可查看范围设置、运行检查并打开最新 HTML
报告。

## 主要检查

- 授权范围和被动模式验证
- 路由、链接、表单、认证入口和 sitemap 发现
- CSP、HSTS、Referrer-Policy、X-Content-Type-Options 等安全响应头
- 认证页面缓存、Cookie 属性、CSRF 候选、GET 登录表单
- OpenAPI、GraphQL、OIDC、JWKS、CORS、CSP 质量、SRI、mixed content
- 敏感文件、source map、调试/管理路径和公开 API 暴露面
- 被动渗透/安全测试报告生成

默认流程不会提交表单、不会爆破、不会发送破坏性 payload。

## 质量门禁

```sh
npm run site:check
npm run security:audit
npm run security:hardening
npm run ci:aegis
npm run gate:ready
```

AIGate 用于 git push 和 CI 质量门禁。Web 控制台专注于 Aegis 检查和报告。

## 文档

- 启用 Pages 后的公开说明网站: <https://leehueeng.github.io/privit-aegis-workspace/>
- 安全扫描说明: [`docs/security-scanning.md`](./docs/security-scanning.md)
- 展示页: [`docs/SHOWCASE.md`](./docs/SHOWCASE.md)
- 示例: [`docs/EXAMPLES.md`](./docs/EXAMPLES.md)
- 架构: [`docs/ARCHITECTURE.md`](./docs/ARCHITECTURE.md)
- FAQ: [`docs/FAQ.md`](./docs/FAQ.md)
- 开源发布检查清单: [`docs/LAUNCH_CHECKLIST.md`](./docs/LAUNCH_CHECKLIST.md)
- GitHub Pages 设置: [`docs/github-pages.md`](./docs/github-pages.md)
- 多语言文档索引: [`docs/LANGUAGES.md`](./docs/LANGUAGES.md)
- 路线图: [`docs/ROADMAP.md`](./docs/ROADMAP.md)
