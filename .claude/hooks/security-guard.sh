#!/bin/bash
# =============================================================================
# Claude Code Security Guard - PreToolUse Hook
# =============================================================================
# プロンプトインジェクションによるシークレット漏洩・情報流出を防ぐ
# 全プロジェクト共通（~/.claude/settings.json から呼び出し）
#
# 対象ツール: Bash, Read, Grep, Write, Edit
# exit 0 = 許可, exit 2 = ブロック
# =============================================================================

INPUT=$(cat)
TOOL_NAME=$(echo "$INPUT" | jq -r '.tool_name // empty')

BLOCK_REASON=""

# =============================================================================
# Bash ツールの検査
# =============================================================================
if [ "$TOOL_NAME" = "Bash" ]; then
  CMD=$(echo "$INPUT" | jq -r '.tool_input.command // empty')

  # -------------------------------------------------------------------------
  # 1. シークレットファイルへのシェルアクセス
  #    Read deny を cat/head/tail 等で迂回する攻撃を防ぐ
  # -------------------------------------------------------------------------
  SENSITIVE_FILES='\.env|\.secret|credentials|\.pem|\.key|id_rsa|id_ed25519|\.pfx|\.p12|htpasswd|shadow|\.netrc|\.npmrc|\.pypirc|\.git-credentials'
  READ_CMDS='cat|head|tail|less|more|bat|nl|od|xxd|strings|hexdump|base64|grep|awk|sed|sort|tee|xargs|source|\.'

  if echo "$CMD" | grep -qEi "(${READ_CMDS})\s+.*(${SENSITIVE_FILES})"; then
    BLOCK_REASON="シークレットファイルへのシェルアクセスをブロック"
  fi

  # find/locate で機密ファイルを探す行為もブロック
  if echo "$CMD" | grep -qEi "(find|locate|mdfind).*(-name|-iname|-path).*($SENSITIVE_FILES).*-exec"; then
    BLOCK_REASON="機密ファイルの検索+実行をブロック"
  fi

  # -------------------------------------------------------------------------
  # 1b. シンボリックリンク/コピー/移動/アーカイブによる迂回攻撃
  #     ln -s .env /tmp/safe.txt → cat /tmp/safe.txt で読まれるのを防ぐ
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qEi "(ln\s+(-[a-zA-Z]*s|-s)[a-zA-Z]*\s+).*(${SENSITIVE_FILES})"; then
    BLOCK_REASON="機密ファイルへのシンボリックリンク作成をブロック"
  fi
  if echo "$CMD" | grep -qEi "(cp|mv|dd|install)\s+.*(${SENSITIVE_FILES})"; then
    BLOCK_REASON="機密ファイルのコピー/移動をブロック"
  fi
  if echo "$CMD" | grep -qEi "(tar|zip|gzip|bzip2|xz|7z)\s+.*(${SENSITIVE_FILES})"; then
    BLOCK_REASON="機密ファイルのアーカイブ化をブロック"
  fi

  # Bash内でファイルを読む際、引数がシンボリックリンクなら実体パスもチェック
  # 例: cat /tmp/notenv.txt → readlink で .env.local と判明 → ブロック
  for FILE_ARG in $(echo "$CMD" | grep -oE '(/[^ ;&|"]+|\./?[^ ;&|"]+)'); do
    if [ -L "$FILE_ARG" ]; then
      RESOLVED=$(readlink -f "$FILE_ARG" 2>/dev/null || true)
      if [ -n "$RESOLVED" ] && echo "$RESOLVED" | grep -qEi "(${SENSITIVE_FILES})"; then
        BLOCK_REASON="シンボリックリンク経由の機密ファイルアクセスをブロック: $FILE_ARG → $RESOLVED"
      fi
    fi
  done

  # -------------------------------------------------------------------------
  # 2. 環境変数のダンプ（シークレットが含まれる可能性）
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qE '(^|\s|;|&&|\|)\s*(env|printenv|export|set)\s*$'; then
    BLOCK_REASON="環境変数の全ダンプをブロック"
  fi

  # 特定のシークレット環境変数の出力
  SECRET_VARS='ANTHROPIC_API_KEY|API_KEY|API_SECRET|SECRET_KEY|ACCESS_TOKEN|AUTH_TOKEN|PRIVATE_KEY|DATABASE_URL|DB_PASSWORD|AWS_SECRET_ACCESS_KEY|AWS_SESSION_TOKEN|GITHUB_TOKEN|SLACK_TOKEN|NOTION_API_KEY|OPENAI_API_KEY|STRIPE_SECRET'
  if echo "$CMD" | grep -qEi "(echo|printf|cat|print)\s.*\\\$(${SECRET_VARS})|\\$\{(${SECRET_VARS})"; then
    BLOCK_REASON="シークレット環境変数の出力をブロック"
  fi

  # -------------------------------------------------------------------------
  # 3. インラインスクリプト（ネットワーク/ファイル操作のバイパス手段）
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qE "(python3?|node|ruby|perl|php)\s+-(c|e)\s"; then
    BLOCK_REASON="インラインスクリプト実行をブロック（セキュリティバイパスの可能性）"
  fi

  # -------------------------------------------------------------------------
  # 4. macOS 固有の攻撃ベクトル
  # -------------------------------------------------------------------------
  # AppleScript（シェルコマンドを間接実行可能）
  if echo "$CMD" | grep -qEi '(^|\s)osascript\s'; then
    BLOCK_REASON="osascript（AppleScript）の実行をブロック"
  fi

  # Keychain アクセス
  if echo "$CMD" | grep -qEi '(^|\s)security\s+(find|dump|delete|add)-'; then
    BLOCK_REASON="macOS Keychainへのアクセスをブロック"
  fi

  # URL経由のデータ送信（open コマンド）
  if echo "$CMD" | grep -qEi '(^|\s)open\s+(https?://|ftp://)'; then
    BLOCK_REASON="open コマンドによるURL送信をブロック"
  fi

  # -------------------------------------------------------------------------
  # 5. ネットワークツール（deny リストの補強）
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qE '(^|\s|;|&&|\|)\s*(nc|ncat|netcat|socat)\s'; then
    BLOCK_REASON="ネットワークツールによるデータ送信をブロック"
  fi

  # -------------------------------------------------------------------------
  # 6. クラウド認証ファイルへのアクセス
  # -------------------------------------------------------------------------
  CLOUD_PATHS='\.aws/(credentials|config)|\.config/gcloud|\.azure/|\.kube/config|\.docker/config\.json|\.config/gh/hosts'
  if echo "$CMD" | grep -qEi "$CLOUD_PATHS"; then
    BLOCK_REASON="クラウド/認証設定ファイルへのアクセスをブロック"
  fi

  # -------------------------------------------------------------------------
  # 7. コマンド履歴ファイル（過去のコマンドにシークレットが含まれる可能性）
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qEi '\.(bash_history|zsh_history|python_history|node_repl_history|lesshst|viminfo)'; then
    BLOCK_REASON="コマンド履歴ファイルへのアクセスをブロック"
  fi

  # -------------------------------------------------------------------------
  # 8. システム情報の詳細取得（攻撃の偵察フェーズ）
  # -------------------------------------------------------------------------
  if echo "$CMD" | grep -qE '(^|\s)(system_profiler|ioreg|networksetup|scutil\s+--get|dscl\s+)'; then
    BLOCK_REASON="システム詳細情報の取得をブロック"
  fi

# =============================================================================
# Read ツールの検査
# =============================================================================
elif [ "$TOOL_NAME" = "Read" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')
  SENSITIVE_READ='\.env($|\.)|\.secret|credentials\.json|\.aws/|\.config/gcloud|\.azure/|\.kube/|\.docker/config|\.npmrc|\.pypirc|\.netrc|\.gnupg/|\.ssh/|\.git-credentials|id_rsa|id_ed25519|\.pem$|\.key$|\.pfx$|\.p12$|\.crt$|\.cer$|htpasswd|shadow|\.bash_history|\.zsh_history|\.config/gh/'

  # 指定パスそのものをチェック
  if echo "$FILE_PATH" | grep -qEi "$SENSITIVE_READ"; then
    BLOCK_REASON="機密ファイルの読み取りをブロック: $(basename "$FILE_PATH")"
  fi

  # シンボリックリンクの場合、実体パスも解決してチェック
  if [ -z "$BLOCK_REASON" ] && [ -L "$FILE_PATH" ]; then
    RESOLVED=$(readlink -f "$FILE_PATH" 2>/dev/null || true)
    if [ -n "$RESOLVED" ] && echo "$RESOLVED" | grep -qEi "$SENSITIVE_READ"; then
      BLOCK_REASON="シンボリックリンク経由の機密ファイル読み取りをブロック: $FILE_PATH → $(basename "$RESOLVED")"
    fi
  fi

# =============================================================================
# Write / Edit ツールの検査（自己保護）
# =============================================================================
elif [ "$TOOL_NAME" = "Write" ] || [ "$TOOL_NAME" = "Edit" ]; then
  FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // empty')

  # セキュリティガード自身と設定ファイルへの書き込みをブロック
  PROTECTED_PATHS='\.claude/hooks/security-guard\.sh|\.claude/settings\.json|\.claude/settings\.local\.json'
  if echo "$FILE_PATH" | grep -qE "$PROTECTED_PATHS"; then
    # ユーザーが直接指示した場合は通す判断をClaude側に委ねる
    # ここではブロックし、ユーザーに手動編集を促す
    BLOCK_REASON="セキュリティ設定ファイルの変更をブロック: $(basename "$FILE_PATH") — 変更が必要な場合はユーザーが直接編集してください"
  fi

# =============================================================================
# Grep ツールの検査
# =============================================================================
elif [ "$TOOL_NAME" = "Grep" ]; then
  SEARCH_PATH=$(echo "$INPUT" | jq -r '.tool_input.path // empty')

  # 機密ディレクトリへの検索
  if echo "$SEARCH_PATH" | grep -qEi '(\.aws|\.ssh|\.gnupg|\.config/gh|\.kube|\.docker)'; then
    BLOCK_REASON="機密ディレクトリの検索をブロック"
  fi
fi

# =============================================================================
# 判定
# =============================================================================
if [ -n "$BLOCK_REASON" ]; then
  echo "SECURITY GUARD: $BLOCK_REASON" >&2
  exit 2
fi

exit 0
