# POP3メール転送ソフトウェア

プロバイダのメールアカウント（POP3）からメールを取得し、同プロバイダのSMTPサーバー経由で指定した任意のメールアドレスに転送するPythonアプリケーション。

## 目的

GmailのPOP3吸出し機能廃止に伴う代替ソリューションとして開発されました。

**主な用途**:
- プロバイダメールをGmail、Outlook、iCloud等の任意のメールサービスに転送
- 複数のメールアカウントを1つのメールボックスに集約
- 使用頻度の低いプロバイダメールを便利なメールサービスに統合

通常のメールソフト（Becky!等）と同等の動作を行うため、プロバイダの利用規約に準拠した安全な動作を保証します。

## 特徴

- 🔄 POP3プロトコルでメール取得
- 📧 プロバイダSMTP経由で転送（通常のメールソフトと同等）
- 🔒 SSL/TLS暗号化通信
- 🗄️ SQLiteで重複管理
- ⏰ ワンショット/デーモンモード対応
- 🗑️ メール保持期間設定（自動削除）
- 📝 日次ログローテーション
- ✅ プロバイダ利用規約に準拠

## セットアップ

### 1. 必要環境

- Python 3.9以上
- プロバイダのメールアカウント（POP3/SMTP対応）
- 転送先メールアドレス（Gmail、Outlook、iCloud等、任意のアドレス）

### 2. 依存ライブラリのインストール

```bash
pip install -r requirements.txt
```

### 3. 簡単セットアップ（推奨）

対話型ウィザードで簡単に設定できます：

```bash
python mail_forwarder.py --setup
```

ウィザードに従って以下の情報を入力してください：
- POP3サーバー情報（ホスト、ポート、ユーザー名、パスワード）
- SMTPサーバー情報（ホスト、ポート、ユーザー名、パスワード）
- 転送先メールアドレス
- メール保持期間

設定完了後、自動的に接続テストが実行されます。

### 4. 手動セットアップ

```bash
cp config.yaml.example config.yaml
```

`config.yaml`を編集して、以下の情報を設定してください：

#### POP3設定（メール取得元）
- `host`: POP3サーバーのホスト名（例: pop.example.ne.jp）
- `port`: POP3ポート（通常995）
- `use_ssl`: SSL/TLS使用（通常true）
- `username`: メールアドレス
- `password`: パスワード

#### SMTP設定（送信用）
- `host`: SMTPサーバーのホスト名（例: smtp.example.ne.jp）
- `port`: SMTPポート（**587推奨** - サブミッションポート/OP25B対策）
- `use_tls`: TLS使用（通常true - STARTTLSを使用）
- `username`: メールアドレス（POP3と同じことが多い）
- `password`: パスワード（POP3と同じことが多い）

#### 転送設定
- `to_address`: 転送先メールアドレス（Gmail、Outlook、iCloud等、任意のアドレス）

#### メール保持期間
- `mail_retention_days`: 転送済みメールの保持期間（0=削除しない、1-365=指定日数後削除、デフォルト30日）

### 5. 接続テスト

設定が正しいか確認します：

```bash
python mail_forwarder.py --test-config
```

POP3とSMTPの接続テストが実行され、問題があれば詳細なエラーメッセージが表示されます。

### 6. プロバイダ別設定例

#### OCN
```yaml
pop3:
  host: pop.ocn.ne.jp
  port: 995
smtp:
  host: smtp.ocn.ne.jp
  port: 587
```

#### ぷらら
```yaml
pop3:
  host: plala.jp
  port: 995
smtp:
  host: plala.jp
  port: 587
```

#### So-net
```yaml
pop3:
  host: pop.so-net.ne.jp
  port: 995
smtp:
  host: mail.so-net.ne.jp
  port: 587
```

#### BIGLOBE
```yaml
pop3:
  host: mail.biglobe.ne.jp
  port: 995
smtp:
  host: mail.biglobe.ne.jp
  port: 587
```

### 7. プロバイダ設定の注意点

#### SMTPポート番号について
- **推奨: ポート587**（サブミッションポート）
  - OP25B（Outbound Port 25 Blocking）対策
  - STARTTLS（use_tls: true）を使用
- ポート465も利用可能
  - SMTP over SSL（最初からSSL接続）
  - ただし587が推奨されています

#### SMTP認証について
- ほとんどのプロバイダでSMTP認証が必須です
- ユーザー名/パスワードはPOP3と同じ場合が多いですが、プロバイダによって異なる場合があります
- プロバイダのマニュアルを確認してください

## 使用方法

### セットアップウィザード

初回セットアップ時に使用します：

```bash
python mail_forwarder.py --setup
```

### 接続テスト

設定が正しいか確認します：

```bash
python mail_forwarder.py --test-config
```

### ワンショットモード（デフォルト）

1回だけメールチェックを実行して終了します。cron/タスクスケジューラでの定期実行に適しています。

```bash
python mail_forwarder.py --once
```

または

```bash
python mail_forwarder.py
```

### デーモンモード

プログラム内で定期的にメールチェックを実行し続けます。

```bash
# デフォルト間隔（300秒=5分）
python mail_forwarder.py --daemon

# カスタム間隔（600秒=10分）
python mail_forwarder.py --daemon --interval 600
```

終了する場合は`Ctrl+C`を押してください。

### 転送開始日時指定（初回テスト用）

過去の大量メールを転送せず、特定の日時以降のメールのみ転送したい場合に使用します。
初回テスト時や本番運用開始時に便利です。

```bash
# 今日（2025年12月30日）以降のメールのみ転送
python mail_forwarder.py --once --start-date 2025-12-30

# 今日の午後3時以降のメールのみ転送
python mail_forwarder.py --once --start-date "2025-12-30 15:00:00"

# 1週間前から転送
python mail_forwarder.py --once --start-date 2025-12-23
```

**注意事項**:
- 日付形式: `YYYY-MM-DD` または `YYYY-MM-DD HH:MM:SS`
- 時分秒を含む場合は引用符で囲む: `"2025-12-30 15:00:00"`
- 指定日時より前のメールはスキップされ、データベースに記録されます（forward_success=False）
- 2回目以降の実行では `--start-date` は不要です（UIDLで自動的に新規メールのみ取得）

**使用例**:
```bash
# 初回テスト: 今日以降のメールだけ転送
python mail_forwarder.py --once --start-date 2025-12-30

# 2回目以降: --start-date は不要（自動的に新規メールのみ取得）
python mail_forwarder.py --once
```

### 設定ファイルのパス指定

```bash
python mail_forwarder.py --config /path/to/config.yaml
```

## 定期実行の設定

### Windows タスクスケジューラ

1. タスクスケジューラを起動
2. 「基本タスクの作成」をクリック
3. タスク名: 「Gmail転送」
4. トリガー: 「毎日」または「コンピューター起動時」
5. 操作: 「プログラムの開始」
6. プログラム: `python`
7. 引数: `C:\path\to\mail_forwarder.py --once`
8. 開始: `C:\path\to\`（プロジェクトディレクトリ）

### Linux/Mac cron

```bash
# crontab -e で編集
# 5分ごとに実行
*/5 * * * * cd /path/to/project && python3 mail_forwarder.py --once >> logs/cron.log 2>&1
```

## メール保持期間設定

`config.yaml`の`mail_retention_days`で、転送済みメールの保持期間を設定できます：

- `0`: メールを削除しない（無期限保持）
- `1-365`: 指定日数経過後に自動削除
- デフォルト: `30`日

**注意**: 転送に失敗したメールは、設定に関わらず削除されません。

## ログ

ログファイルは`logs/mail_forwarder.log`に出力されます。

- 日次ローテーション（午前0時）
- 30日間保持
- ログレベルは`config.yaml`で設定可能

## トラブルシューティング

### 設定エラー

**エラー**: 設定ファイルが見つかりません

**対処法**:
```bash
python mail_forwarder.py --setup
```
または
```bash
cp config.yaml.example config.yaml
```

### 接続エラー

**エラー**: POP3サーバーに接続できませんでした

**対処法**:
- POP3サーバーのホスト名、ポート番号を確認
- ファイアウォール設定を確認
- SSL/TLS設定を確認
- `python mail_forwarder.py --test-config` で詳細を確認

### 認証エラー

**エラー**: POP3/SMTP認証に失敗しました

**対処法**:
- ユーザー名、パスワードを確認
- プロバイダの設定マニュアルを確認
- SMTP認証が有効になっているか確認
- パスワードに特殊文字が含まれる場合、YAMLでシングルクォートで囲む
  ```yaml
  password: 'p@ssw0rd#123'
  ```

### メールが転送されない

**対処法**:
- ログファイル（`logs/mail_forwarder.log`）を確認
- データベース（`data/mail_uidl.db`）が破損していないか確認
- 転送先アドレス（`forward.to_address`）が正しいか確認
- `python mail_forwarder.py --test-config` で接続テスト

### SMTP送信エラー

**エラー**: SMTP認証に失敗しました

**対処法**:
- ポート587を使用しているか確認（推奨）
- `use_tls: true`が設定されているか確認
- プロバイダがSMTP認証を要求しているか確認
- ユーザー名とパスワードがPOP3と異なる場合があります（プロバイダのマニュアル確認）

### よくあるエラーと解決方法

#### SSL/TLSエラー

```
SSLError: [SSL: CERTIFICATE_VERIFY_FAILED]
```

**対処法**: プロバイダの証明書が正しいか確認。ファイアウォールやアンチウイルスソフトが通信を妨げていないか確認。

#### タイムアウトエラー

```
TimeoutError: Connection timed out
```

**対処法**: ネットワーク接続を確認。ファイアウォールでポート995（POP3）や587（SMTP）がブロックされていないか確認。

## セキュリティについて

- 設定ファイル（config.yaml）にはパスワードが含まれるため、適切に管理してください
- config.yamlは.gitignoreに含まれており、Gitにコミットされません
- 通信は全てSSL/TLS暗号化されます

## ライセンス

このソフトウェアはプロジェクト内部使用を目的としています。

## 作成日

2025年12月30日
