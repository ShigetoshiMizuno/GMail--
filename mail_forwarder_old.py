#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Gmail転送ソフトウェア
POP3からメールを取得してプロバイダSMTP経由で転送する
"""

import argparse
import poplib
import smtplib
import sqlite3
import signal
import sys
import time
import yaml
import logging
from datetime import datetime, timedelta
from email import message_from_bytes
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import parseaddr
from logging.handlers import TimedRotatingFileHandler
from pathlib import Path
from typing import List, Dict, Optional, Tuple


class MailForwarder:
    """メール転送クラス"""
    
    def __init__(self, config_path: str = "config.yaml"):
        """
        初期化
        
        Args:
            config_path: 設定ファイルパス
        """
        self.config = self._load_config(config_path)
        self.logger = self._setup_logging()
        self.db_path = self.config['database']['path']
        self.running = True
        
        # シグナルハンドラ設定
        signal.signal(signal.SIGINT, self._signal_handler)
        signal.signal(signal.SIGTERM, self._signal_handler)
        
        # データベース初期化
        self._init_database()
    
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
        ''', (uidl, datetime.now(), from_addr, subject, success))
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
        ''', (cutoff_date,))
        
        mails_to_delete = cursor.fetchall()
        
        if not mails_to_delete:
            self.logger.debug("削除対象のメールはありません")
            conn.close()
            return
        
        # POP3サーバーに接続してメール削除
        try:
            pop_config = self.config['pop3']
            if pop_config['use_ssl']:
                pop_conn = poplib.POP3_SSL(pop_config['host'], pop_config['port'])
            else:
                pop_conn = poplib.POP3(pop_config['host'], pop_config['port'])
            
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
    
    def _fetch_new_mails(self) -> List[Tuple[str, bytes, str, str]]:
        """
        新規メールを取得
        
        Returns:
            (UIDL, メール本文, 送信者, 件名)のリスト
        """
        pop_config = self.config['pop3']
        new_mails = []
        
        try:
            # POP3接続
            if pop_config['use_ssl']:
                pop_conn = poplib.POP3_SSL(pop_config['host'], pop_config['port'])
            else:
                pop_conn = poplib.POP3(pop_config['host'], pop_config['port'])
            
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
            
            self.logger.info(
                f"サーバー上のメール: {len(server_uidls)}通, "
                f"新規メール: {len(new_uidls)}通"
            )
            
            # 新規メール取得
            for uidl in new_uidls:
                msg_num = server_uidls[uidl]
                resp, lines, octets = pop_conn.retr(msg_num)
                mail_data = b'\r\n'.join(lines)
                
                # メール解析
                msg = message_from_bytes(mail_data)
                from_addr = parseaddr(msg.get('From', ''))[1]
                subject = msg.get('Subject', '(件名なし)')
                
                new_mails.append((uidl, mail_data, from_addr, subject))
                self.logger.info(
                    f"新規メール取得: From={from_addr} Subject={subject}"
                )
            
            pop_conn.quit()
            
        except Exception as e:
            self.logger.error(f"メール取得中にエラーが発生しました: {e}")
        
        return new_mails
    
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
            # SMTP接続（ポート番号により接続方法を分岐）
            if smtp_config['port'] == 465:
                # ポート465: SMTP over SSL
                smtp_conn = smtplib.SMTP_SSL(
                    smtp_config['host'], 
                    smtp_config['port']
                )
            else:
                # ポート587等: STARTTLS
                smtp_conn = smtplib.SMTP(
                    smtp_config['host'], 
                    smtp_config['port']
                )
                
                if smtp_config.get('use_tls', True):
                    smtp_conn.starttls()
            
            # 認証
            smtp_conn.login(smtp_config['username'], smtp_config['password'])
            
            # 元のメールをそのまま転送
            smtp_conn.sendmail(
                smtp_config['username'],     # 転送元（プロバイダアカウント）
                forward_config['to_address'], # 転送先（Gmail等）
                mail_data
            )
            
            smtp_conn.quit()
            
            self.logger.info(
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
    
    def process_once(self):
        """ワンショット処理"""
        self.logger.info("=" * 60)
        self.logger.info("メールチェック開始（ワンショットモード）")
        self.logger.info("=" * 60)
        
        # 古いメール削除
        self._delete_old_mails()
        
        # 新規メール取得
        new_mails = self._fetch_new_mails()
        
        # メール転送
        for uidl, mail_data, from_addr, subject in new_mails:
            success = self._forward_mail(mail_data, from_addr, subject)
            self._save_retrieved_mail(uidl, from_addr, subject, success)
        
        self.logger.info(f"処理完了: {len(new_mails)}通のメールを処理しました")
        self.logger.info("=" * 60)
    
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
        description='Gmail転送ソフトウェア - POP3からメールを取得してプロバイダSMTP経由で転送'
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
    
    args = parser.parse_args()
    
    # デフォルトはワンショットモード
    if not args.daemon:
        args.once = True
    
    # フォワーダー初期化
    forwarder = MailForwarder(args.config)
    
    # モード実行
    if args.daemon:
        interval = args.interval if args.interval else \
                   forwarder.config['daemon'].get('interval', 300)
        forwarder.process_daemon(interval)
    else:
        forwarder.process_once()


if __name__ == '__main__':
    main()
