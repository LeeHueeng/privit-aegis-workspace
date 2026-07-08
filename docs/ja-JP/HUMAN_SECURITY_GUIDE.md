# Aegis CLI ユーザーセキュリティガイド

Aegis CLI は、チームが所有またはテスト承認を受けたサービスに対して、承認済みで非破壊のセキュリティチェックを実行するためのツールです。

## クイックスタート

```bash
npm install
npm run catalog:generate
npm run aegis -- init
npm run aegis -- scope verify
npm run aegis -- plan --mode passive --target frontend
npm run aegis -- run --target frontend --mode passive
npm run aegis -- report --format html
```

## 承認とスコープ

`aegis.scope.json` は必須です。プロジェクト、環境、有効な対象、許可 host/path、拒否 path、承認所有者、証明方式、有効期限、安全制限を記録します。本番環境は既定で passive-only です。

## フロントエンド異常キャプチャ

フロントエンドチェックは、ヘッダー、コンソールエラー、失敗したネットワーク概要、スクリーンショット、DOM スナップショットなどの安全なブラウザ/ランタイム証拠を収集します。

## バックエンド/API テスト

API チェックは安全カタログから選択されます。認証および role matrix チェックには明示的な承認と専用テストアカウントが必要です。

## DB 読み取り専用監査

データベース監査モードは読み取り専用の設定レビューに限定されます。書き込みクエリ、スキーマ変更、データダンプはポリシーでブロックされます。

## サプライチェーン検査

CI モードは SAST、SCA、SBOM、コンテナ、IaC、secret scanning 連携向けです。

## Docker 使用方法

```bash
docker build -t aegis/security-cli .
docker run --rm -v "$PWD:/workspace" aegis/security-cli run --scope aegis.scope.json
```

## npm 使用方法

パッケージには `security:init`、`security:plan`、`security:frontend`、`security:api`、`security:ci`、`security:report` スクリプトが含まれます。

## CI/CD 使用方法

`aegis scope verify`、`aegis plan --mode ci`、`aegis run --mode ci` を実行し、`aegis report --format sarif` で SARIF を生成します。

## レポートと修正

レポートにはスコープ、環境、スキャン設定、重要度別 finding、artifact、認証 matrix プレースホルダー、サプライチェーン準備状況、DB 監査準備状況、修正ガイドが含まれます。
