# Privit Aegis Workspace

[English](./README.md) · [한국어](./README.ko.md) · [日本語](./README.ja.md) · [中文](./README.zh-CN.md) · [GitHub Pages](https://leehueeng.github.io/privit-aegis-workspace/)

Privit Aegis Workspace は、Privit Web アプリ向けの認可済みセキュリティ
テスト用ワークスペースです。Aegis CLI、ローカル Web コンソール、
パッシブなサイト探索、セキュリティレポート、多言語ドキュメント、
AI 支援プロンプト、AIGate のプッシュ品質ゲートをひとつのリポジトリで
扱います。

## 注目ポイント

- Web コンソールと CLI が同じスコープと同じ品質基準を使います。
- 韓国語、英語、日本語、中国語の README とガイドを提供します。
- レポートには実行した検査、合格基準、保持された証拠、推奨対応が
  明記されます。
- AI は検査結果の判定には使わず、設定確認、準備状況、修正プロンプトの
  生成を支援します。
- GitHub Actions は最小権限と固定された Action 参照で構成されます。

## クイックスタート

```sh
npm run setup
npm run web
```

`http://127.0.0.1:4317` を開くと、スコープ設定、検査実行、最新 HTML
レポートの確認ができます。

## 主な検査

- 認可済みスコープとパッシブモードの確認
- ルート、リンク、フォーム、認証候補、サイトマップの探索
- CSP、HSTS、Referrer-Policy、X-Content-Type-Options などのヘッダー検査
- 認証ページのキャッシュ、Cookie 属性、CSRF 候補、GET ログインフォーム
- OpenAPI、GraphQL、OIDC、JWKS、CORS、CSP 品質、SRI、mixed content
- 機密ファイル、ソースマップ、デバッグ/管理者パス、公開 API 面の確認
- パッシブな侵入テストレポートの生成

既定ではフォーム送信、総当たり、破壊的なペイロードは実行しません。

## 品質ゲート

```sh
npm run site:check
npm run security:audit
npm run security:hardening
npm run ci:aegis
npm run gate:ready
```

AIGate は git push と CI 品質ゲート用です。Web コンソールは Aegis の
検査とレポート作成に集中します。

## ドキュメント

- Pages 有効化後の公開サイト: <https://leehueeng.github.io/privit-aegis-workspace/>
- セキュリティ検査ガイド: [`docs/security-scanning.md`](./docs/security-scanning.md)
- ショーケース: [`docs/SHOWCASE.md`](./docs/SHOWCASE.md)
- 例: [`docs/EXAMPLES.md`](./docs/EXAMPLES.md)
- 公開ローンチチェックリスト: [`docs/LAUNCH_CHECKLIST.md`](./docs/LAUNCH_CHECKLIST.md)
- GitHub Pages 設定: [`docs/github-pages.md`](./docs/github-pages.md)
- 多言語ドキュメント: [`docs/LANGUAGES.md`](./docs/LANGUAGES.md)
- ロードマップ: [`docs/ROADMAP.md`](./docs/ROADMAP.md)
