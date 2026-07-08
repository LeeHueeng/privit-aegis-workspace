# Aegis CLI 用户安全指南

Aegis CLI 帮助团队对其拥有或已获授权测试的服务运行授权、非破坏性的安全检查。

## 快速开始

```bash
npm install
npm run catalog:generate
npm run aegis -- init
npm run aegis -- scope verify
npm run aegis -- plan --mode passive --target frontend
npm run aegis -- run --target frontend --mode passive
npm run aegis -- report --format html
```

## 授权和范围

`aegis.scope.json` 是必需文件。它记录项目、环境、启用目标、允许的 host/path、拒绝的 path、授权所有者、证明方式、到期时间和安全限制。生产环境默认为 passive-only。

## 前端异常捕获

前端检查会收集安全的浏览器/运行时证据，例如 headers、console errors、失败网络摘要、screenshots 和 DOM snapshots。

## 后端/API 测试

API 检查从安全目录中选择。认证和 role matrix 检查需要明确批准和专用测试账号。

## 数据库只读审计

数据库审计模式仅限只读配置审查。写查询、schema 变更和数据转储会被策略阻止。

## 供应链扫描

CI 模式用于 SAST、SCA、SBOM、容器、IaC 和 secret scanning 集成。

## Docker 用法

```bash
docker build -t aegis/security-cli .
docker run --rm -v "$PWD:/workspace" aegis/security-cli run --scope aegis.scope.json
```

## npm 用法

该包包含 `security:init`、`security:plan`、`security:frontend`、`security:api`、`security:ci` 和 `security:report` 脚本。

## CI/CD 用法

运行 `aegis scope verify`、`aegis plan --mode ci`、`aegis run --mode ci`，然后用 `aegis report --format sarif` 生成 SARIF。

## 报告和修复

报告包括范围、环境、扫描配置、按严重级别分组的 finding、artifact、认证 matrix 占位、供应链准备状态、DB 审计准备状态和修复建议。
