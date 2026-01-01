#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POP3メール転送ソフトウェア
POP3からメールを取得してプロバイダSMTP経由で任意のアドレスに転送する
"""

import argparse
import poplib
import smtplib
import sqlite3
import signal
import ssl
import sys
import time
import yaml
import logging
import getpass
from datetime import datetime, timedelta, timezone
from email import message_from_bytes
from email.header import decode_header
from email.utils import parseaddr, parsedate_to_datetime
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import List, Dict, Optional, Tuple


def decode_mail_header(header_value: str) -> str:
    """
    メールヘッダー（Subject等）をデコードして読みやすい文字列に変換
    エンコーディング名を先頭に表示
    
    Args:
        header_value: エンコードされたヘッダー値
    
    Returns:
        デコードされた文字列（例: "[UTF-8] 件名"）
    """
    if not header_value:
        return "(件名なし)"
    
    try:
        decoded_parts = []
        detected_encoding = None
        
        for part, encoding in decode_header(header_value):
            if isinstance(part, bytes):
                # 最初のエンコーディングを記録
                if detected_encoding is None and encoding:
                    detected_encoding = encoding.upper()
                
                # エンコーディングが指定されている場合はそれを使用
                if encoding:
                    try:
                        decoded_parts.append(part.decode(encoding))
                    except (UnicodeDecodeError, LookupError):
                        # エンコーディング失敗時はUTF-8で試行
                        try:
                            decoded_parts.append(part.decode('utf-8'))
                            if detected_encoding is None:
                                detected_encoding = 'UTF-8'
                        except UnicodeDecodeError:
                            # それでも失敗したら文字を置き換えて表示
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                            if detected_encoding is None:
                                detected_encoding = 'UTF-8'
                else:
                    # エンコーディング不明の場合、一般的なエンコーディングを試行
                    for enc in ['utf-8', 'iso-2022-jp', 'shift_jis', 'gbk']:
                        try:
                            decoded_parts.append(part.decode(enc))
                            if detected_encoding is None:
                                detected_encoding = enc.upper()
                            break
                        except (UnicodeDecodeError, LookupError):
                            continue
                    else:
                        # すべて失敗したら置き換え
                        decoded_parts.append(part.decode('utf-8', errors='replace'))
                        if detected_encoding is None:
                            detected_encoding = 'UNKNOWN'
            else:
                # 文字列の場合はそのまま追加
                decoded_parts.append(str(part))
        
        decoded_text = ''.join(decoded_parts)
        
        # エンコーディング情報を先頭に追加
        if detected_encoding:
            return f"[{detected_encoding}] {decoded_text}"
        else:
            return f"[ASCII] {decoded_text}"
            
    except Exception:
        # デコード完全失敗時は元の文字列を返す
        return f"[RAW] {header_value}"


def input_with_default(prompt: str, default: str) -> str:
    """デフォルト値付き入力"""
    value = input(f"{prompt} [{default}]: ").strip()
    return value if value else default


def parse_start_date(date_string: str) -> datetime:
    """
    開始日時文字列をdatetimeに変換
    
    対応形式:
    - YYYY-MM-DD (例: 2025-12-30)
    - YYYY-MM-DD HH:MM:SS (例: 2025-12-30 15:30:00)
    
    Args:
        date_string: 日付文字列
    
    Returns:
        datetime: 変換後の日時（JST）
    
    Raises:
        ValueError: 不正なフォーマット
    """
    # まず時分秒付きを試す
    try:
        dt = datetime.strptime(date_string, '%Y-%m-%d %H:%M:%S')
        # JSTタイムゾーンを付与
        return dt.replace(tzinfo=timezone(timedelta(hours=9)))
    except ValueError:
        pass
    
    # 次に日付のみを試す
    try:
        dt = datetime.strptime(date_string, '%Y-%m-%d')
        # JSTタイムゾーンを付与
        return dt.replace(tzinfo=timezone(timedelta(hours=9)))
    except ValueError:
        raise ValueError(
            "日付形式が不正です。以下の形式で指定してください:\n"
            "  YYYY-MM-DD (例: 2025-12-30)\n"
            "  YYYY-MM-DD HH:MM:SS (例: 2025-12-30 15:30:00)"
        )


def create_pop3_connection(host: str, port: int, use_ssl: bool = True, 
                          logger: Optional[logging.Logger] = None):
    """
    POP3サーバーに接続（自動フォールバック付き）
    
    Args:
        host: POP3サーバーのホスト名
        port: POP3ポート番号
        use_ssl: SSL/TLS使用フラグ
        logger: ロガー（オプション）
    
    Returns:
        POP3接続オブジェクト
    """
    if not use_ssl:
        # 非SSL接続
        return poplib.POP3(host, port)
    
    # SSL接続を試行
    try:
        # 【試行1】通常のセキュリティレベルで接続
        if logger:
            logger.debug("POP3接続試行中（標準セキュリティ）...")
        
        context = ssl.create_default_context()
        pop_conn = poplib.POP3_SSL(host, port, context=context)
        
        if logger:
            logger.info("POP3接続成功（標準セキュリティ）")
        
        return pop_conn
        
    except ssl.SSLError as e:
        # DH_KEY_TOO_SMALL エラーの場合のみフォールバック
        if 'dh key too small' in str(e).lower():
            if logger:
                logger.warning(
                    "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    "⚠️  古いサーバー検出\n"
                    "━━━━━━━━━━━━━━━━━━━━━━━━\n"
                    f"サーバー {host} は古い暗号化方式を使用しています。\n"
                    "セキュリティレベルを下げて再接続します...\n"
                    "（自宅LAN内での使用であれば問題ありません）"
                )
            
            # 【試行2】セキュリティレベルを下げて再接続
            try:
                context = ssl.create_default_context()
                context.set_ciphers('DEFAULT@SECLEVEL=1')
                
                pop_conn = poplib.POP3_SSL(host, port, context=context)
                
                if logger:
                    logger.info("POP3接続成功（低セキュリティモード）")
                
                return pop_conn
                
            except Exception as retry_error:
                if logger:
                    logger.error(f"セキュリティレベルを下げても接続失敗: {retry_error}")
                raise
        else:
            # DH_KEY_TOO_SMALL以外のSSLエラーは再スロー
            raise


def setup_wizard():
    """対話型セットアップウィザード"""
    print("━━━━━━━━━━━━━━━━━━━━━━━━")
    print("  POP3メール転送ツール セットアップ")
    print("━━━━━━━━━━━━━━━━━━━━━━━━")
    print()
    print("config.yamlを作成します。")
    print()
    
    # POP3設定
    print("【POP3設定】")
    pop3_host = input("POP3サーバーのホスト名: ").strip()
    pop3_port = input_with_default("ポート番号", "995")
    pop3_username = input("ユーザー名: ").strip()
    pop3_password = getpass.getpass("パスワード: ")
    print()
    
    # SMTP設定
    print("【SMTP設定】")
    smtp_host = input("SMTPサーバーのホスト名: ").strip()
    smtp_port = input_with_default("ポート番号", "587")
    smtp_username = input("ユーザー名: ").strip()
    smtp_password = getpass.getpass("パスワード: ")
    pop_before_smtp_input = input_with_default("POP before SMTPを使用しますか？ (y/n)", "n")
    pop_before_smtp = pop_before_smtp_input.lower() == 'y'
    print()
    
    # 転送設定
    print("【転送設定】")
    to_address = input("転送先メールアドレス: ").strip()
    print()
    
    # メール保持設定
    print("【メール保持設定】")
    retention_days = input_with_default("保持期間（日数、0=削除しない）", "30")
    print()
    
    # config.yaml作成
    config = {
        'pop3': {
            'host': pop3_host,
            'port': int(pop3_port),
            'use_ssl': True,
            'username': pop3_username,
            'password': pop3_password
        },
        'smtp': {
            'host': smtp_host,
            'port': int(smtp_port),
            'use_tls': True,
            'username': smtp_username,
            'password': smtp_password,
            'pop_before_smtp': pop_before_smtp
        },
        'forward': {
            'to_address': to_address
        },
        'mail_retention_days': int(retention_days),
        'daemon': {
            'interval': 300
        },
        'database': {
            'path': 'data/mail_uidl.db'
        },
        'logging': {
            'level': 'INFO',
            'file': 'logs/mail_forwarder.log',
            'max_days': 30
        }
    }
    
    with open('config.yaml', 'w', encoding='utf-8') as f:
        yaml.dump(config, f, allow_unicode=True, default_flow_style=False, sort_keys=False)
    
    print("config.yamlを作成しました！✓")
    print()
    
    # 接続テスト
    test = input("接続テストを実行しますか？ (y/n): ").strip().lower()
    if test == 'y':
        print()
        test_config('config.yaml')


def test_config(config_path: str = 'config.yaml'):
    """設定ファイルの接続テスト"""
    print("設定ファイルをテストしています...")
    print()
    
    try:
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
    except FileNotFoundError:
        print(f"❌ エラー: 設定ファイル '{config_path}' が見つかりません")
        print()
        print("ヒント: python mail_forwarder.py --setup でセットアップしてください")
        return False
    except yaml.YAMLError as e:
        print(f"❌ エラー: 設定ファイルの読み込みに失敗しました: {e}")
        return False
    
    success = True
    
    # POP3接続テスト
    print("[1/2] POP3接続テスト")
    pop3_config = config['pop3']
    print(f"  ホスト: {pop3_config['host']}:{pop3_config['port']}")
    
    try:
        print("  接続中... ", end='', flush=True)
        pop_conn = create_pop3_connection(
            pop3_config['host'],
            pop3_config['port'],
            pop3_config.get('use_ssl', True)
        )
        print("✓ 成功")
        
        print("  認証中... ", end='', flush=True)
        pop_conn.user(pop3_config['username'])
        pop_conn.pass_(pop3_config['password'])
        print("✓ 成功")
        
        pop_conn.quit()
        print()
    except poplib.error_proto as e:
        print(f"✗ 失敗")
        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print("エラー: POP3認証に失敗しました")
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print("考えられる原因:")
        print("・ユーザー名またはパスワードが間違っている")
        print("・POP3サーバーでの認証が無効になっている")
        print()
        print("対処方法:")
        print("1. config.yamlのpop3.usernameとpop3.passwordを確認")
        print("2. プロバイダの管理画面でPOP3が有効か確認")
        print()
        print(f"詳細エラー: {e}")
        print()
        success = False
    except Exception as e:
        print(f"✗ 失敗")
        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print("エラー: POP3サーバーに接続できませんでした")
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print("考えられる原因:")
        print("・ホスト名が間違っている")
        print("・ポート番号が間違っている（POP3/SSLは通常995番）")
        print("・ファイアウォールでブロックされている")
        print("・インターネット接続が切断されている")
        print()
        print("ヒント: config.yamlのpop3.hostとpop3.portを確認してください")
        print()
        print(f"詳細エラー: {e}")
        print()
        success = False
    
    # SMTP接続テスト
    print("[2/2] SMTP接続テスト")
    smtp_config = config['smtp']
    print(f"  ホスト: {smtp_config['host']}:{smtp_config['port']}")
    
    # POP before SMTPのテスト
    if smtp_config.get('pop_before_smtp', False):
        print()
        print("  [POP before SMTP有効]")
        print("  POP3認証を実行中... ", end='', flush=True)
        try:
            pop3_config = config['pop3']
            pop_conn = create_pop3_connection(
                pop3_config['host'],
                pop3_config['port'],
                pop3_config.get('use_ssl', True)
            )
            
            pop_conn.user(pop3_config['username'])
            pop_conn.pass_(pop3_config['password'])
            pop_conn.quit()
            print("✓ 成功")
        except Exception as e:
            print(f"✗ 失敗: {e}")
            success = False
    
    try:
        print("  接続中... ", end='', flush=True)
        if smtp_config['port'] == 465:
            smtp_conn = smtplib.SMTP_SSL(smtp_config['host'], smtp_config['port'], timeout=10)
            print("✓ 成功")
        else:
            smtp_conn = smtplib.SMTP(smtp_config['host'], smtp_config['port'], timeout=10)
            print("✓ 成功")
            
            if smtp_config.get('use_tls', True):
                print("  TLS開始... ", end='', flush=True)
                smtp_conn.starttls()
                print("✓ 成功")
        
        print("  認証中... ", end='', flush=True)
        smtp_conn.login(smtp_config['username'], smtp_config['password'])
        print("✓ 成功")
        
        smtp_conn.quit()
        print()
    except smtplib.SMTPAuthenticationError as e:
        print(f"✗ 失敗")
        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print("エラー: SMTP認証に失敗しました")
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print("考えられる原因:")
        print("・ユーザー名またはパスワードが間違っている")
        print("・パスワードに特殊文字（#, @, : 等）が含まれている")
        print("・プロバイダでSMTP認証が無効になっている")
        print()
        print("対処方法:")
        print("1. config.yamlのsmtp.usernameとsmtp.passwordを確認")
        print("2. パスワードに特殊文字がある場合は 'パスワード' のように")
        print("   シングルクォートで囲んでください")
        print("3. プロバイダの管理画面でSMTP認証が有効か確認")
        print()
        print(f"詳細エラー: {e}")
        print()
        success = False
    except Exception as e:
        print(f"✗ 失敗")
        print()
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print("エラー: SMTPサーバーに接続できませんでした")
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
        print("考えられる原因:")
        print("・ホスト名が間違っている")
        print("・ポート番号が間違っている（推奨: 587番）")
        print("・ファイアウォールでブロックされている")
        print("・TLS設定が間違っている")
        print()
        print("ヒント: config.yamlのsmtp.hostとsmtp.portを確認してください")
        print()
        print(f"詳細エラー: {e}")
        print()
        success = False
    
    if success:
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print("すべてのテストに合格しました！ 🎉")
        print("━━━━━━━━━━━━━━━━━━━━━━━━")
        print()
    
    return success


class MailForwarder:
    """メール転送クラス"""
    
    def __init__(self, config_path: str = "config.yaml", start_date: Optional[datetime] = None):
        """
        初期化
        
        Args:
            config_path: 設定ファイルパス
            start_date: 転送開始日時（この日時以降のメールのみ転送）
        """
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.db_path = self.config['database']['path']
        self.running = True
        self.start_date = start_date
        
        # シグナルハンドラ設定
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # データベース初期化
        self._init_database()
        
        # 転送開始日時をログに記録
        if self.start_date:
            self.logger.info(
                f"転送開始日時: {self.start_date.strftime('%Y年%m月%d日 %H:%M:%S')} 以降"
            )
    
    def _load_config(self, config_path: str) -> dict:
        """
        設定ファイルを読み込む
        
        Args:
            config_path: 設定ファイルパス
            
        Returns:
            設定辞書
        """
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return yaml.safe_load(f)
        except FileNotFoundError:
            print(f"エラー: 設定ファイル '{config_path}' が見つかりません")
            print("config.yaml.example をコピーして config.yaml を作成してください")
            print("または python mail_forwarder.py --setup でセットアップしてください")
            sys.exit(1)
        except yaml.YAMLError as e:
            print(f"エラー: 設定ファイルの読み込みに失敗しました: {e}")
            sys.exit(1)
    
    def _setup_logging(self) -> logging.Logger:
        """
        ロギング設定
        
        Returns:
            ロガーオブジェクト
        """
        # ログディレクトリ作成
        log_file = self.config['logging']['file']
        log_dir = Path(log_file).parent
        log_dir.mkdir(parents=True, exist_ok=True)
        
        # ロガー作成
        logger = logging.getLogger('MailForwarder')
        logger.setLevel(self.config['logging']['level'])
        
        # ハンドラ作成（日次ローテーション）
        handler = TimedRotatingFileHandler(
            log_file,
            when='midnight',
            interval=1,
            backupCount=self.config['logging'].get('max_days', 30),
            encoding='utf-8'
        )
        
        # フォーマッタ設定
        formatter = logging.Formatter(
            '[%(asctime)s] %(levelname)s - %(message)s',
            datefmt='%Y-%m-%d %H:%M:%S'
        )
        handler.setFormatter(formatter)
        logger.addHandler(handler)
        
        # コンソール出力も追加
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(formatter)
        logger.addHandler(console_handler)
        
        return logger
    
    def _init_database(self):
        """データベース初期化"""
        # データディレクトリ作成
        db_dir = Path(self.db_path).parent
        db_dir.mkdir(parents=True, exist_ok=True)
        
        # テーブル作成
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS retrieved_mails (
                uidl TEXT PRIMARY KEY,
                forwarded_at DATETIME,
                from_addr TEXT,
                subject TEXT,
                forward_success BOOLEAN
            )
        ''')
        conn.commit()
        conn.close()
        self.logger.info(f"データベース初期化完了: {self.db_path}")
    
    def _signal_handler(self, signum, frame):
        """シグナルハンドラ"""
        self.logger.info(f"シグナル {signum} を受信しました。終了します...")
        self.running = False
    
    def _get_retrieved_uidls(self) -> set:
        """
        取得済みUIDLリストを取得
        
        Returns:
            取得済みUIDLのセット
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT uidl FROM retrieved_mails')
        uidls = {row[0] for row in cursor.fetchall()}
        conn.close()
        return uidls
    
    def _save_retrieved_mail(self, uidl: str, from_addr: str, subject: str, 
                           success: bool):
        """
        取得済みメール情報を保存
        
        Args:
            uidl: UIDL
            from_addr: 送信者
            subject: 件名
            success: 転送成功フラグ
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT OR REPLACE INTO retrieved_mails 
            (uidl, forwarded_at, from_addr, subject, forward_success)
            VALUES (?, ?, ?, ?, ?)
        ''', (uidl, datetime.now().isoformat(), from_addr, subject, success))
        conn.commit()
        conn.close()
    
    def _delete_old_mails(self):
        """保持期間を超えた転送済みメールを削除"""
        retention_days = self.config.get('mail_retention_days', 30)
        
        # 0日の場合は削除しない
        if retention_days == 0:
            self.logger.debug("mail_retention_days=0 のため、メール削除をスキップします")
            return
        
        # 削除対象日時を計算
        cutoff_date = datetime.now() - timedelta(days=retention_days)
        
        # 削除対象のUIDLリストを取得
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            SELECT uidl, from_addr, subject FROM retrieved_mails
            WHERE forward_success = 1
            AND forwarded_at < ?
        ''', (cutoff_date.isoformat(),))
        
        mails_to_delete = cursor.fetchall()
        
        if not mails_to_delete:
            self.logger.debug("削除対象のメールはありません")
            conn.close()
            return
        
        # POP3サーバーに接続してメール削除
        try:
            pop_config = self.config['pop3']
            pop_conn = create_pop3_connection(
                pop_config['host'],
                pop_config['port'],
                pop_config.get('use_ssl', True),
                self.logger
            )
            
            pop_conn.user(pop_config['username'])
            pop_conn.pass_(pop_config['password'])
            
            # サーバー上の全UIDLを取得
            resp, uidl_list, octets = pop_conn.uidl()
            server_uidls = {}
            for item in uidl_list:
                parts = item.decode('utf-8').split()
                msg_num = int(parts[0])
                uidl = parts[1]
                server_uidls[uidl] = msg_num
            
            # 削除実行
            deleted_count = 0
            for uidl, from_addr, subject in mails_to_delete:
                if uidl in server_uidls:
                    msg_num = server_uidls[uidl]
                    pop_conn.dele(msg_num)
                    deleted_count += 1
                    self.logger.info(
                        f"メール削除: UIDL={uidl[:20]}... "
                        f"From={from_addr} Subject={subject}"
                    )
                else:
                    # サーバーに存在しない場合はDB削除のみ
                    self.logger.debug(
                        f"サーバーに存在しないメール: UIDL={uidl[:20]}..."
                    )
                
                # DBからも削除
                cursor.execute('DELETE FROM retrieved_mails WHERE uidl = ?', (uidl,))
            
            conn.commit()
            pop_conn.quit()
            
            self.logger.info(
                f"保持期間({retention_days}日)を超えたメールを {deleted_count} 通削除しました"
            )
            
        except Exception as e:
            self.logger.error(f"メール削除中にエラーが発生しました: {e}")
        finally:
            conn.close()
    
    def _fetch_new_mails(self) -> List[Tuple[str, bytes, str, str, Optional[datetime]]]:
        """
        新規メールを取得
        
        Returns:
            (UIDL, メール本文, 送信者, 件名, メール日時)のリスト
        """
        pop_config = self.config['pop3']
        new_mails = []
        
        try:
            # POP3接続
            pop_conn = create_pop3_connection(
                pop_config['host'],
                pop_config['port'],
                pop_config.get('use_ssl', True),
                self.logger
            )
            
            self.logger.info(f"POP3サーバーに接続: {pop_config['host']}")
            
            # 認証
            pop_conn.user(pop_config['username'])
            pop_conn.pass_(pop_config['password'])
            
            # UIDL取得
            resp, uidl_list, octets = pop_conn.uidl()
            server_uidls = {}
            for item in uidl_list:
                parts = item.decode('utf-8').split()
                msg_num = int(parts[0])
                uidl = parts[1]
                server_uidls[uidl] = msg_num
            
            # 取得済みUIDL取得
            retrieved_uidls = self._get_retrieved_uidls()
            
            # 新規メール特定
            new_uidls = set(server_uidls.keys()) - retrieved_uidls
            
            # 新規メール取得
            skipped_count = 0
            for uidl in new_uidls:
                msg_num = server_uidls[uidl]
                resp, lines, octets = pop_conn.retr(msg_num)
                mail_data = b'\r\n'.join(lines)
                
                # メール解析
                msg = message_from_bytes(mail_data)
                from_addr = parseaddr(msg.get('From', ''))[1]
                subject_raw = msg.get('Subject', '(件名なし)')
                subject = decode_mail_header(subject_raw)
                
                # メールの日付を取得
                mail_date = None
                try:
                    mail_date_str = msg.get('Date')
                    if mail_date_str:
                        mail_date = parsedate_to_datetime(mail_date_str)
                        # タイムゾーンなしの場合はJSTと仮定
                        if mail_date.tzinfo is None:
                            mail_date = mail_date.replace(tzinfo=timezone(timedelta(hours=9)))
                except Exception:
                    pass
                
                # 転送開始日時でフィルタ
                should_forward = True
                if self.start_date and mail_date:
                    # 開始日時より前のメールはスキップ
                    if mail_date < self.start_date:
                        should_forward = False
                        skipped_count += 1
                        # DEBUGレベルで詳細を記録（ノイズ防止）
                        self.logger.debug(
                            f"スキップ: {mail_date.strftime('%Y-%m-%d %H:%M:%S')} のメール "
                            f"From={from_addr} Subject={subject} （開始日時より前）"
                        )
                        # スキップしたメールもUIDLに記録（forward_success=False）
                        self._save_retrieved_mail(uidl, from_addr, subject, False)
                elif self.start_date and not mail_date:
                    # Dateヘッダーがない場合は警告して転送する
                    self.logger.warning(
                        f"Dateヘッダーがありません。転送します: From={from_addr} Subject={subject}"
                    )
                
                if should_forward:
                    new_mails.append((uidl, mail_data, from_addr, subject, mail_date))
                    # DEBUGレベルで詳細を記録
                    self.logger.debug(
                        f"新規メール取得: From={from_addr} Subject={subject}"
                    )
            
            pop_conn.quit()
            
        except Exception as e:
            self.logger.error(f"メール取得中にエラーが発生しました: {e}")
        
        return new_mails
    
    def _authenticate_pop_before_smtp(self):
        """POP before SMTP認証"""
        try:
            self.logger.info("POP before SMTP認証を実行中...")
            
            pop_config = self.config['pop3']
            
            # POP3接続
            pop_conn = create_pop3_connection(
                pop_config['host'],
                pop_config['port'],
                pop_config.get('use_ssl', True),
                self.logger
            )
            
            # 認証
            pop_conn.user(pop_config['username'])
            pop_conn.pass_(pop_config['password'])
            
            # すぐに切断（メールは取得しない）
            pop_conn.quit()
            
            self.logger.info("POP before SMTP認証成功")
            
        except Exception as e:
            self.logger.error(f"POP before SMTP認証失敗: {e}")
            raise
    
    def _forward_mail(self, mail_data: bytes, from_addr: str, subject: str) -> bool:
        """
        メールを転送
        
        Args:
            mail_data: メール本文
            from_addr: 送信者
            subject: 件名
            
        Returns:
            転送成功フラグ
        """
        smtp_config = self.config['smtp']
        forward_config = self.config['forward']
        
        try:
            # POP before SMTPが有効な場合、先に認証
            if smtp_config.get('pop_before_smtp', False):
                self._authenticate_pop_before_smtp()
            
            # SMTP接続（ポート番号により接続方法を分岐）
            self.logger.debug(f"SMTP接続開始: {smtp_config['host']}:{smtp_config['port']}")
            if smtp_config['port'] == 465:
                # ポート465: SMTP over SSL
                smtp_conn = smtplib.SMTP_SSL(
                    smtp_config['host'], 
                    smtp_config['port'],
                    timeout=30
                )
            else:
                # ポート587等: STARTTLS
                smtp_conn = smtplib.SMTP(
                    smtp_config['host'], 
                    smtp_config['port'],
                    timeout=30
                )
                
                if smtp_config.get('use_tls', True):
                    self.logger.debug("STARTTLS開始...")
                    smtp_conn.starttls()
                    self.logger.debug("STARTTLS完了")
            
            self.logger.debug("SMTP接続成功")
            
            # 認証（POP before SMTPの場合はスキップ）
            if not smtp_config.get('pop_before_smtp', False):
                self.logger.debug("SMTP認証開始...")
                smtp_conn.login(smtp_config['username'], smtp_config['password'])
                self.logger.debug("SMTP認証成功")
            else:
                self.logger.debug("POP before SMTP使用のため、SMTP認証はスキップ")
            
            # 元のメールをそのまま転送
            smtp_conn.sendmail(
                smtp_config['username'],     # 転送元（プロバイダアカウント）
                forward_config['to_address'], # 転送先（Gmail等）
                mail_data
            )
            
            smtp_conn.quit()
            
            # DEBUGレベルで詳細を記録
            self.logger.debug(
                f"メール転送成功: From={from_addr} Subject={subject} "
                f"To={forward_config['to_address']}"
            )
            return True
            
        except Exception as e:
            self.logger.error(
                f"メール転送失敗: From={from_addr} Subject={subject} "
                f"エラー: {e}"
            )
            return False
    
    def _forward_mail_batch(self, mails: List[Tuple]) -> List[Tuple[str, bool]]:
        """
        複数メールを1つのSMTP接続で転送（効率化・レート制限対策）
        
        Args:
            mails: [(uidl, mail_data, from_addr, subject, mail_date), ...]
            
        Returns:
            [(uidl, success), ...] 転送結果のリスト
        """
        smtp_config = self.config['smtp']
        forward_config = self.config['forward']
        results = []
        
        if not mails:
            return results
        
        try:
            # POP before SMTPが有効な場合、先に認証
            if smtp_config.get('pop_before_smtp', False):
                self._authenticate_pop_before_smtp()
                # POP認証後、少し待機（サーバー側の処理待ち）
                time.sleep(2)
            
            # SMTP接続（ポート番号により接続方法を分岐）
            self.logger.debug(f"SMTP接続開始: {smtp_config['host']}:{smtp_config['port']}")
            if smtp_config['port'] == 465:
                # ポート465: SMTP over SSL
                smtp_conn = smtplib.SMTP_SSL(
                    smtp_config['host'], 
                    smtp_config['port'],
                    timeout=30
                )
            else:
                # ポート587等: STARTTLS
                smtp_conn = smtplib.SMTP(
                    smtp_config['host'], 
                    smtp_config['port'],
                    timeout=30
                )
                
                if smtp_config.get('use_tls', True):
                    self.logger.debug("STARTTLS開始...")
                    smtp_conn.starttls()
                    self.logger.debug("STARTTLS完了")
            
            self.logger.debug("SMTP接続成功")
            
            # 認証試行
            auth_success = False
            
            # POP before SMTPでも認証が必要なケースに対応
            try:
                if smtp_config.get('username') and smtp_config.get('password'):
                    self.logger.debug("SMTP認証開始...")
                    smtp_conn.login(smtp_config['username'], smtp_config['password'])
                    self.logger.debug("SMTP認証成功")
                    auth_success = True
                else:
                    self.logger.debug("SMTP認証情報なし、認証スキップ")
                    auth_success = True  # 認証不要と判断
            except smtplib.SMTPAuthenticationError:
                # 認証エラーの場合、POP before SMTPのみで続行を試みる
                if smtp_config.get('pop_before_smtp', False):
                    self.logger.debug("SMTP認証失敗、POP before SMTPのみで続行")
                    auth_success = True
                else:
                    raise
            
            # メール送信ループ
            for i, (uidl, mail_data, from_addr, subject, mail_date) in enumerate(mails, 1):
                try:
                    # メール送信
                    smtp_conn.sendmail(
                        smtp_config['username'],     # 転送元（プロバイダアカウント）
                        forward_config['to_address'], # 転送先（Gmail等）
                        mail_data
                    )
                    
                    self.logger.debug(
                        f"メール転送成功 [{i}/{len(mails)}]: From={from_addr} Subject={subject}"
                    )
                    results.append((uidl, True))
                    
                    # 送信間隔（レート制限対策）
                    # 最後のメール以外は待機
                    if i < len(mails):
                        interval = smtp_config.get('send_interval', 1)
                        if interval > 0:
                            self.logger.debug(f"{interval}秒待機中...")
                            time.sleep(interval)
                    
                except Exception as e:
                    self.logger.error(
                        f"メール転送失敗 [{i}/{len(mails)}]: From={from_addr} Subject={subject} "
                        f"エラー: {e}"
                    )
                    results.append((uidl, False))
            
            smtp_conn.quit()
            self.logger.debug("SMTP接続を正常に終了")
            
        except Exception as e:
            self.logger.error(f"SMTP接続エラー: {e}")
            # 接続エラーの場合、全メールを失敗扱い
            for uidl, _, _, _, _ in mails:
                if not any(r[0] == uidl for r in results):
                    results.append((uidl, False))
        
        return results
    
    def process_once(self):
        """ワンショット処理"""
        self.logger.info("=" * 60)
        self.logger.info("メールチェック開始（ワンショットモード）")
        self.logger.info("=" * 60)
        
        # 古いメール削除
        self._delete_old_mails()
        
        # 新規メール取得
        new_mails = self._fetch_new_mails()
        
        # カウンターと詳細リスト
        forwarded_count = 0
        failed_count = 0
        forwarded_details = []
        failed_details = []
        
        # メール転送（バッチ処理で効率化）
        if new_mails:
            self.logger.info(f"{len(new_mails)}件のメールを転送中...")
            batch_results = self._forward_mail_batch(new_mails)
            
            # 結果を処理
            for (uidl, mail_data, from_addr, subject, mail_date), (result_uidl, success) in zip(new_mails, batch_results):
                self._save_retrieved_mail(uidl, from_addr, subject, success)
                
                if success:
                    forwarded_count += 1
                    forwarded_details.append({
                        'from': from_addr,
                        'subject': subject,
                        'date': mail_date
                    })
                else:
                    failed_count += 1
                    failed_details.append({
                        'from': from_addr,
                        'subject': subject,
                        'date': mail_date
                    })
        
        # サマリー表示
        self.logger.info("")
        self.logger.info("━" * 60)
        self.logger.info("メールチェック結果")
        self.logger.info("━" * 60)
        self.logger.info(f"新規メール: {len(new_mails)}件")
        
        # スキップ件数を表示（start_date指定時）
        if self.start_date:
            # UIDLからスキップ件数を推定（今回の新規 - 転送対象）
            # 正確なカウントは_fetch_new_mailsで計算
            pass
        
        self.logger.info(f"  転送成功: {forwarded_count}件")
        
        if failed_count > 0:
            self.logger.info(f"  転送失敗: {failed_count}件")
        
        self.logger.info("━" * 60)
        
        # 転送成功メールの詳細表示
        if forwarded_count > 0:
            self.logger.info("")
            self.logger.info("【転送成功メール詳細】")
            
            for i, mail in enumerate(forwarded_details, 1):
                self.logger.info(f"[{i}/{forwarded_count}] From: {mail['from']}")
                self.logger.info(f"      Subject: {mail['subject']}")
                if mail['date']:
                    self.logger.info(f"      Date: {mail['date'].strftime('%Y-%m-%d %H:%M:%S')}")
                self.logger.info(f"      → 転送成功 ✓")
                self.logger.info("")
        
        # 転送失敗メールの詳細表示
        if failed_count > 0:
            self.logger.info("")
            self.logger.info("【転送失敗メール詳細】")
            
            for i, mail in enumerate(failed_details, 1):
                self.logger.info(f"[{i}/{failed_count}] From: {mail['from']}")
                self.logger.info(f"      Subject: {mail['subject']}")
                if mail['date']:
                    self.logger.info(f"      Date: {mail['date'].strftime('%Y-%m-%d %H:%M:%S')}")
                self.logger.info(f"      → 転送失敗 ✗")
                self.logger.info("")
        
        self.logger.info("━" * 60)
        self.logger.info(f"完了: {forwarded_count}件のメールを転送しました")
        self.logger.info("━" * 60)
    
    def process_daemon(self, interval: int):
        """
        デーモン処理
        
        Args:
            interval: チェック間隔（秒）
        """
        self.logger.info("=" * 60)
        self.logger.info(f"デーモンモード開始（チェック間隔: {interval}秒）")
        self.logger.info("=" * 60)
        
        while self.running:
            try:
                # 古いメール削除
                self._delete_old_mails()
                
                # 新規メール取得
                new_mails = self._fetch_new_mails()
                
                # メール転送
                for uidl, mail_data, from_addr, subject in new_mails:
                    success = self._forward_mail(mail_data, from_addr, subject)
                    self._save_retrieved_mail(uidl, from_addr, subject, success)
                
                self.logger.info(
                    f"処理完了: {len(new_mails)}通のメールを処理しました"
                )
                
                # インターバル
                if self.running:
                    self.logger.info(f"{interval}秒待機します...")
                    time.sleep(interval)
                    
            except Exception as e:
                self.logger.error(f"エラーが発生しました: {e}")
                if self.running:
                    self.logger.info(f"{interval}秒後に再試行します...")
                    time.sleep(interval)
        
        self.logger.info("デーモンモードを終了しました")


def main():
    """メイン関数"""
    parser = argparse.ArgumentParser(
        description='POP3メール転送ソフトウェア - POP3からメールを取得してプロバイダSMTP経由で転送'
    )
    parser.add_argument(
        '--once',
        action='store_true',
        help='ワンショットモードで実行（デフォルト）'
    )
    parser.add_argument(
        '--daemon',
        action='store_true',
        help='デーモンモードで実行'
    )
    parser.add_argument(
        '--interval',
        type=int,
        help='チェック間隔（秒、デーモンモード時のみ有効）'
    )
    parser.add_argument(
        '--config',
        type=str,
        default='config.yaml',
        help='設定ファイルのパス（デフォルト: config.yaml）'
    )
    parser.add_argument(
        '--setup',
        action='store_true',
        help='対話型セットアップウィザードを起動'
    )
    parser.add_argument(
        '--test-config',
        action='store_true',
        help='設定ファイルの接続テストを実行'
    )
    parser.add_argument(
        '--start-date',
        type=str,
        help='この日時以降のメールのみ転送（初回テスト用）\n'
             '形式: YYYY-MM-DD または YYYY-MM-DD HH:MM:SS\n'
             '例: 2025-12-30 または "2025-12-30 15:30:00"'
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help='詳細ログを出力（DEBUGレベル）'
    )
    
    args = parser.parse_args()
    
    # セットアップウィザード
    if args.setup:
        setup_wizard()
        return
    
    # 接続テスト
    if args.test_config:
        test_config(args.config)
        return
    
    # デフォルトはワンショットモード
    if not args.daemon:
        args.once = True
    
    # 転送開始日時の解析
    start_date = None
    if args.start_date:
        try:
            start_date = parse_start_date(args.start_date)
            print(f"転送開始日時: {start_date.strftime('%Y年%m月%d日 %H:%M:%S')} 以降")
        except ValueError as e:
            print(f"エラー: {e}")
            sys.exit(1)
    
    # フォワーダー初期化
    forwarder = MailForwarder(args.config, start_date)
    
    # verboseモードの場合、ログレベルをDEBUGに変更
    if args.verbose:
        forwarder.logger.setLevel(logging.DEBUG)
        for handler in forwarder.logger.handlers:
            handler.setLevel(logging.DEBUG)
        forwarder.logger.debug("DEBUGモードが有効になりました")
    
    # モード実行
    if args.daemon:
        interval = args.interval if args.interval else \
                   forwarder.config['daemon'].get('interval', 300)
        forwarder.process_daemon(interval)
    else:
        forwarder.process_once()


if __name__ == '__main__':
    main()
