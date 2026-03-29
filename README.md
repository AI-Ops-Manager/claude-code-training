# Terrackathon Template

## 使い方

1. このリポジトリをクローン
   ```
   git clone <URL>
   ```
2. Claude Codeでこのフォルダを開く
3. 「何を作りたいか一緒に考えよう」と話しかける

## 含まれているもの

| ファイル | 役割 |
|---------|------|
| CLAUDE.md | AIへの指示書（初心者向けに設計済み） |
| .claude/settings.json | セキュリティ設定（設定済み） |
| .claude/hooks/security-guard.sh | セキュリティガード（自動実行） |
| .env.example | 環境変数のテンプレート |
| .gitignore | .env除外設定 |

## セキュリティについて

このテンプレートには、AIが危険な操作をしないためのガードレールが設定済みです。
設定を変更する必要はありません。そのまま使ってください。
