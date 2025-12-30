#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
POP3メール転送ソフトウェア - ユニットテスト
"""

import pytest
import sqlite3
import tempfile
import shutil
import time
from pathlib import Path
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, MagicMock, patch, mock_open, call
import yaml
import poplib
import smtplib
from email.utils import parseaddr

# テスト対象のモジュールをインポート
from mail_forwarder import (
    input_with_default,
    setup_wizard,
    test_config,
    MailForwarder,
    parse_start_date
)


class TestParseStartDate:
    """parse_start_date関数のテスト"""
    
    def test_parse_date_only(self):
        """日付のみ（YYYY-MM-DD）のパース成功"""
        dt = parse_start_date('2025-12-30')
        
        assert dt.year == 2025
        assert dt.month == 12
        assert dt.day == 30
        assert dt.hour == 0
        assert dt.minute == 0
        assert dt.second == 0
        # JSTタイムゾーン（UTC+09:00）
        assert dt.tzinfo == timezone(timedelta(hours=9))
    
    def test_parse_datetime(self):
        """時分秒付き（YYYY-MM-DD HH:MM:SS）のパース成功"""
        dt = parse_start_date('2025-12-30 15:30:00')
        
        assert dt.year == 2025
        assert dt.month == 12
        assert dt.day == 30
        assert dt.hour == 15
        assert dt.minute == 30
        assert dt.second == 0
        # JSTタイムゾーン（UTC+09:00）
        assert dt.tzinfo == timezone(timedelta(hours=9))
    
    def test_parse_datetime_midnight(self):
        """深夜0時の時刻指定"""
        dt = parse_start_date('2025-12-30 00:00:00')
        
        assert dt.hour == 0
        assert dt.minute == 0
        assert dt.second == 0
    
    def test_parse_datetime_end_of_day(self):
        """23時59分59秒の時刻指定"""
        dt = parse_start_date('2025-12-30 23:59:59')
        
        assert dt.hour == 23
        assert dt.minute == 59
        assert dt.second == 59
    
    def test_invalid_format_slash(self):
        """不正な形式（スラッシュ区切り）でエラー"""
        with pytest.raises(ValueError) as excinfo:
            parse_start_date('2025/12/30')
        
        # エラーメッセージに2つの形式例が含まれることを確認
        error_message = str(excinfo.value)
        assert 'YYYY-MM-DD' in error_message
        assert 'YYYY-MM-DD HH:MM:SS' in error_message
    
    def test_invalid_date(self):
        """存在しない日付でエラー"""
        with pytest.raises(ValueError):
            parse_start_date('2025-02-30')
    
    def test_invalid_month(self):
        """存在しない月でエラー"""
        with pytest.raises(ValueError):
            parse_start_date('2025-13-01')
    
    def test_empty_string(self):
        """空文字列でエラー"""
        with pytest.raises(ValueError):
            parse_start_date('')
    
    def test_invalid_time_format(self):
        """不正な時刻形式でエラー"""
        with pytest.raises(ValueError):
            parse_start_date('2025-12-30 25:00:00')  # 25時は存在しない
    
    def test_partial_datetime(self):
        """時だけ・分だけ指定はエラー"""
        with pytest.raises(ValueError):
            parse_start_date('2025-12-30 15')


class TestInputWithDefault:
    """input_with_default関数のテスト"""
    
    def test_with_user_input(self):
        """ユーザー入力がある場合"""
        with patch('builtins.input', return_value='user_value'):
            result = input_with_default("Enter value", "default")
            assert result == 'user_value'
    
    def test_with_empty_input(self):
        """空入力の場合、デフォルト値を返す"""
        with patch('builtins.input', return_value=''):
            result = input_with_default("Enter value", "default")
            assert result == 'default'
    
    def test_with_whitespace_input(self):
        """空白のみの入力の場合、デフォルト値を返す"""
        with patch('builtins.input', return_value='   '):
            result = input_with_default("Enter value", "default")
            assert result == 'default'


class TestSetupWizard:
    """setup_wizard関数のテスト"""
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.dump')
    @patch('mail_forwarder.test_config')
    @patch('getpass.getpass')
    @patch('builtins.input')
    def test_setup_wizard_with_test(self, mock_input, mock_getpass, 
                                    mock_test_config, mock_yaml_dump, mock_file):
        """セットアップウィザードが正常に動作し、接続テストを実行する"""
        # モック入力値の設定（順序重要）
        mock_input.side_effect = [
            'pop.test.jp',     # POP3ホスト
            '',                # POP3ポート（デフォルト995を使用）
            'user@test.jp',    # POP3ユーザー名
            'smtp.test.jp',    # SMTPホスト
            '',                # SMTPポート（デフォルト587を使用）
            'smtp@test.jp',    # SMTPユーザー名
            '',                # POP before SMTP（デフォルトn）
            'dest@test.jp',    # 転送先
            '',                # 保持期間（デフォルト30を使用）
            'y'                # 接続テストを実行
        ]
        mock_getpass.side_effect = ['pop_password', 'smtp_password']
        
        setup_wizard()
        
        # config.yamlが作成されることを確認
        mock_file.assert_called_once_with('config.yaml', 'w', encoding='utf-8')
        
        # yaml.dumpが呼ばれることを確認
        assert mock_yaml_dump.called
        config = mock_yaml_dump.call_args[0][0]
        
        # 設定内容の検証
        assert config['pop3']['host'] == 'pop.test.jp'
        assert config['pop3']['port'] == 995
        assert config['pop3']['username'] == 'user@test.jp'
        assert config['pop3']['password'] == 'pop_password'
        assert config['smtp']['host'] == 'smtp.test.jp'
        assert config['smtp']['port'] == 587
        assert config['smtp']['username'] == 'smtp@test.jp'
        assert config['smtp']['password'] == 'smtp_password'
        assert config['forward']['to_address'] == 'dest@test.jp'
        assert config['mail_retention_days'] == 30
        
        # 接続テストが呼ばれることを確認
        mock_test_config.assert_called_once_with('config.yaml')
    
    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.dump')
    @patch('mail_forwarder.test_config')
    @patch('getpass.getpass')
    @patch('builtins.input')
    def test_setup_wizard_without_test(self, mock_input, mock_getpass,
                                       mock_test_config, mock_yaml_dump, mock_file):
        """セットアップウィザードで接続テストをスキップ"""
        mock_input.side_effect = [
            'pop.test.jp', '', 'user@test.jp',
            'smtp.test.jp', '', 'smtp@test.jp', '',
            'dest@test.jp', '',
            'n'  # 接続テストをスキップ
        ]
        mock_getpass.side_effect = ['pop_password', 'smtp_password']
        
        setup_wizard()
        
        # 接続テストが呼ばれないことを確認
        mock_test_config.assert_not_called()


class TestTestConfig:
    """test_config関数のテスト"""
    
    @patch('builtins.print')
    def test_config_file_not_found(self, mock_print):
        """設定ファイルが見つからない場合"""
        result = test_config('nonexistent.yaml')
        assert result is False
        # エラーメッセージが出力されることを確認
        assert any('エラー' in str(call) for call in mock_print.call_args_list)
    
    @patch('builtins.print')
    @patch('builtins.open', mock_open(read_data='invalid: yaml: content: ['))
    def test_invalid_yaml(self, mock_print):
        """不正なYAMLファイルの場合"""
        result = test_config('config.yaml')
        assert result is False
    
    @patch('smtplib.SMTP')
    @patch('poplib.POP3_SSL')
    @patch('builtins.open', mock_open(read_data='''
pop3:
  host: pop.test.jp
  port: 995
  use_ssl: true
  username: test@test.jp
  password: testpass
smtp:
  host: smtp.test.jp
  port: 587
  use_tls: true
  username: test@test.jp
  password: testpass
'''))
    @patch('builtins.print')
    def test_successful_connection(self, mock_print, mock_pop3, mock_smtp):
        """正常に接続できる場合"""
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        
        # SMTPモックの設定
        smtp_instance = MagicMock()
        mock_smtp.return_value = smtp_instance
        
        result = test_config('config.yaml')
        
        assert result is True
        # 成功メッセージが出力されることを確認
        assert any('合格' in str(call) or '成功' in str(call) 
                  for call in mock_print.call_args_list)
    
    @patch('poplib.POP3_SSL')
    @patch('builtins.open', mock_open(read_data='''
pop3:
  host: pop.test.jp
  port: 995
  use_ssl: true
  username: test@test.jp
  password: wrongpass
smtp:
  host: smtp.test.jp
  port: 587
'''))
    @patch('builtins.print')
    def test_pop3_auth_failure(self, mock_print, mock_pop3):
        """POP3認証に失敗する場合"""
        mock_pop3.side_effect = poplib.error_proto('Authentication failed')
        
        result = test_config('config.yaml')
        
        assert result is False
    
    @patch('poplib.POP3_SSL')
    @patch('builtins.open', mock_open(read_data='''
pop3:
  host: pop.test.jp
  port: 995
  use_ssl: true
  username: test@test.jp
  password: wrongpass
smtp:
  host: smtp.test.jp
  port: 587
'''))
    @patch('builtins.print')
    def test_pop3_auth_failure_japanese_message(self, mock_print, mock_pop3):
        """POP3認証失敗時に日本語エラーメッセージが表示される"""
        mock_pop3.side_effect = poplib.error_proto('Authentication failed')
        
        result = test_config('config.yaml')
        
        assert result is False
        # 日本語のエラーメッセージが出力されることを確認
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any('認証' in call or 'エラー' in call for call in print_calls)
    
    @patch('smtplib.SMTP')
    @patch('poplib.POP3_SSL')
    @patch('builtins.open', mock_open(read_data='''
pop3:
  host: pop.test.jp
  port: 995
  use_ssl: true
  username: test@test.jp
  password: testpass
smtp:
  host: smtp.test.jp
  port: 587
  use_tls: true
  username: test@test.jp
  password: wrongpass
'''))
    @patch('builtins.print')
    def test_smtp_auth_failure_japanese_message(self, mock_print, mock_pop3, mock_smtp):
        """SMTP認証失敗時に日本語エラーメッセージが表示される"""
        # POP3は成功
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        
        # SMTPは認証失敗
        mock_smtp.side_effect = smtplib.SMTPAuthenticationError(535, 'Authentication failed')
        
        result = test_config('config.yaml')
        
        assert result is False
        # 日本語のエラーメッセージが出力されることを確認
        print_calls = [str(call) for call in mock_print.call_args_list]
        assert any('SMTP' in call and ('認証' in call or 'エラー' in call) for call in print_calls)


class TestMailForwarder:
    """MailForwarderクラスのテスト"""
    
    @pytest.fixture
    def temp_dir(self):
        """テスト用の一時ディレクトリを作成"""
        temp_path = tempfile.mkdtemp()
        yield temp_path
        # ロガーのハンドラーをクローズして解放
        import logging
        logger = logging.getLogger('MailForwarder')
        handlers = logger.handlers[:]
        for handler in handlers:
            try:
                handler.close()
            except:
                pass
            logger.removeHandler(handler)
        # 少し待ってからディレクトリ削除
        time.sleep(0.1)
        try:
            shutil.rmtree(temp_path)
        except PermissionError:
            pass  # Windowsでロックされている場合は無視
    
    @pytest.fixture
    def config_file(self, temp_dir):
        """テスト用の設定ファイルを作成"""
        config = {
            'pop3': {
                'host': 'pop.test.jp',
                'port': 995,
                'use_ssl': True,
                'username': 'test@test.jp',
                'password': 'testpass'
            },
            'smtp': {
                'host': 'smtp.test.jp',
                'port': 587,
                'use_tls': True,
                'username': 'test@test.jp',
                'password': 'testpass'
            },
            'forward': {
                'to_address': 'dest@test.jp'
            },
            'mail_retention_days': 30,
            'daemon': {
                'interval': 300
            },
            'database': {
                'path': f'{temp_dir}/mail_uidl.db'
            },
            'logging': {
                'level': 'INFO',
                'file': f'{temp_dir}/test.log',
                'max_days': 30
            }
        }
        
        config_path = Path(temp_dir) / 'config.yaml'
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)
        
        return str(config_path)
    
    def test_init(self, config_file, temp_dir):
        """初期化のテスト"""
        forwarder = MailForwarder(config_file)
        
        assert forwarder.config is not None
        assert forwarder.logger is not None
        assert forwarder.running is True
        assert forwarder.start_date is None  # デフォルトはNone
        
        # データベースが作成されることを確認
        db_path = Path(temp_dir) / 'mail_uidl.db'
        assert db_path.exists()
        
        # テーブルが作成されることを確認
        conn = sqlite3.connect(str(db_path))
        cursor = conn.cursor()
        cursor.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='retrieved_mails'"
        )
        assert cursor.fetchone() is not None
        conn.close()
    
    def test_init_with_start_date(self, config_file):
        """start_dateを指定して初期化"""
        start_dt = datetime(2025, 12, 30, 15, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        assert forwarder.start_date == start_dt
    
    def test_init_with_start_date_logs(self, config_file, temp_dir):
        """start_date設定時にログに記録される"""
        start_dt = datetime(2025, 12, 30, 15, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # ログファイルを読んで確認
        log_file = Path(temp_dir) / 'test.log'
        with open(log_file, 'r', encoding='utf-8') as f:
            log_content = f.read()
        
        assert '転送開始日時' in log_content
        assert '2025年12月30日 15:00:00' in log_content
    
    def test_load_config_file_not_found(self):
        """存在しない設定ファイルを読み込もうとした場合"""
        with pytest.raises(SystemExit):
            MailForwarder('nonexistent.yaml')
    
    def test_get_retrieved_uidls_empty(self, config_file):
        """取得済みUIDLが空の場合"""
        forwarder = MailForwarder(config_file)
        uidls = forwarder._get_retrieved_uidls()
        assert len(uidls) == 0
        assert isinstance(uidls, set)
    
    def test_save_and_get_retrieved_mail(self, config_file):
        """メール情報の保存と取得"""
        forwarder = MailForwarder(config_file)
        
        # メール情報を保存
        forwarder._save_retrieved_mail(
            'uidl123',
            'sender@test.jp',
            'Test Subject',
            True
        )
        
        # 取得できることを確認
        uidls = forwarder._get_retrieved_uidls()
        assert 'uidl123' in uidls
        
        # データベースの内容を確認
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT * FROM retrieved_mails WHERE uidl = ?', ('uidl123',))
        row = cursor.fetchone()
        conn.close()
        
        assert row is not None
        assert row[0] == 'uidl123'  # uidl
        assert row[2] == 'sender@test.jp'  # from_addr
        assert row[3] == 'Test Subject'  # subject
        assert row[4] == 1  # forward_success (True -> 1)
    
    def test_save_retrieved_mail_replace(self, config_file):
        """同じUIDLで再保存した場合、上書きされる"""
        forwarder = MailForwarder(config_file)
        
        # 1回目の保存
        forwarder._save_retrieved_mail('uidl123', 'old@test.jp', 'Old', False)
        
        # 2回目の保存（同じUIDL）
        forwarder._save_retrieved_mail('uidl123', 'new@test.jp', 'New', True)
        
        # 1件だけ存在することを確認
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT COUNT(*) FROM retrieved_mails WHERE uidl = ?', ('uidl123',))
        count = cursor.fetchone()[0]
        assert count == 1
        
        # 新しい情報で上書きされていることを確認
        cursor.execute('SELECT from_addr, subject, forward_success FROM retrieved_mails WHERE uidl = ?', ('uidl123',))
        row = cursor.fetchone()
        conn.close()
        
        assert row[0] == 'new@test.jp'
        assert row[1] == 'New'
        assert row[2] == 1
    
    @patch('poplib.POP3_SSL')
    def test_delete_old_mails_retention_zero(self, mock_pop3, config_file, temp_dir):
        """mail_retention_days=0の場合、削除しない"""
        # 設定を変更
        config_path = Path(config_file)
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        config['mail_retention_days'] = 0
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)
        
        forwarder = MailForwarder(config_file)
        
        # 古いメールを登録
        old_date = datetime.now() - timedelta(days=60)
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO retrieved_mails (uidl, forwarded_at, from_addr, subject, forward_success)
            VALUES (?, ?, ?, ?, ?)
        ''', ('old_uidl', old_date, 'test@test.jp', 'Old Mail', True))
        conn.commit()
        conn.close()
        
        # 削除処理を実行
        forwarder._delete_old_mails()
        
        # POP3接続されないことを確認
        mock_pop3.assert_not_called()
        
        # メールが残っていることを確認
        uidls = forwarder._get_retrieved_uidls()
        assert 'old_uidl' in uidls
    
    @patch('poplib.POP3_SSL')
    def test_delete_old_mails_success(self, mock_pop3, config_file):
        """古いメールの削除が成功する"""
        forwarder = MailForwarder(config_file)
        
        # 古い転送成功メールを登録
        old_date = datetime.now() - timedelta(days=60)
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO retrieved_mails (uidl, forwarded_at, from_addr, subject, forward_success)
            VALUES (?, ?, ?, ?, ?)
        ''', ('old_uidl', old_date, 'test@test.jp', 'Old Mail', True))
        
        # 新しいメールも登録
        new_date = datetime.now()
        cursor.execute('''
            INSERT INTO retrieved_mails (uidl, forwarded_at, from_addr, subject, forward_success)
            VALUES (?, ?, ?, ?, ?)
        ''', ('new_uidl', new_date, 'test@test.jp', 'New Mail', True))
        
        conn.commit()
        conn.close()
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 old_uidl', b'2 new_uidl'],
            0
        )
        
        # 削除処理を実行
        forwarder._delete_old_mails()
        
        # POP3接続されることを確認
        mock_pop3.assert_called_once()
        
        # 古いメールが削除されることを確認
        pop_instance.dele.assert_called_once_with(1)
        
        # データベースから削除されていることを確認
        uidls = forwarder._get_retrieved_uidls()
        assert 'old_uidl' not in uidls
        assert 'new_uidl' in uidls
    
    @patch('poplib.POP3_SSL')
    def test_delete_old_mails_failed_forward_not_deleted(self, mock_pop3, config_file):
        """転送失敗したメールは削除しない"""
        forwarder = MailForwarder(config_file)
        
        # 古いが転送失敗したメールを登録
        old_date = datetime.now() - timedelta(days=60)
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO retrieved_mails (uidl, forwarded_at, from_addr, subject, forward_success)
            VALUES (?, ?, ?, ?, ?)
        ''', ('failed_uidl', old_date, 'test@test.jp', 'Failed Mail', False))
        conn.commit()
        conn.close()
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (b'+OK', [], 0)
        
        # 削除処理を実行
        forwarder._delete_old_mails()
        
        # POP3接続されないことを確認（削除対象がないため）
        # または接続されても dele が呼ばれないことを確認
        if mock_pop3.called:
            pop_instance.dele.assert_not_called()
        
        # メールが残っていることを確認
        uidls = forwarder._get_retrieved_uidls()
        assert 'failed_uidl' in uidls
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_empty(self, mock_pop3, config_file):
        """新規メールがない場合"""
        forwarder = MailForwarder(config_file)
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (b'+OK', [], 0)
        
        new_mails = forwarder._fetch_new_mails()
        
        assert len(new_mails) == 0
        assert isinstance(new_mails, list)
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_mails(self, mock_pop3, config_file):
        """新規メールがある場合"""
        forwarder = MailForwarder(config_file)
        
        # テスト用メールデータ（\nを\r\nに統一）
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: Test Mail',
            b'Date: Mon, 30 Dec 2025 12:00:00 +0900',
            b'',
            b'This is a test mail.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl123'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        assert len(new_mails) == 1
        uidl, mail_data, from_addr, subject = new_mails[0]
        assert uidl == 'uidl123'
        assert b'This is a test mail' in mail_data
        assert from_addr == 'sender@test.jp'
        assert subject == 'Test Mail'
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_skip_retrieved(self, mock_pop3, config_file):
        """既に取得済みのメールはスキップする"""
        forwarder = MailForwarder(config_file)
        
        # 既に取得済みとして登録
        forwarder._save_retrieved_mail('uidl123', 'test@test.jp', 'Old', True)
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl123'],  # 既に取得済み
            0
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # 新規メールとして取得されないことを確認
        assert len(new_mails) == 0
        pop_instance.retr.assert_not_called()
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_start_date_filter_old(self, mock_pop3, config_file):
        """start_dateより古いメールはスキップする"""
        # 開始日時: 2025-12-30 00:00:00 JST
        start_dt = datetime(2025, 12, 30, 0, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # 2025-12-29のメール（スキップ対象）
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: Old Mail',
            b'Date: Mon, 29 Dec 2025 23:59:59 +0900',  # 12/29 23:59:59
            b'',
            b'This is an old mail.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_old'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # スキップされるので転送対象は0件
        assert len(new_mails) == 0
        
        # スキップしたメールはUIDLに記録される（forward_success=False）
        uidls = forwarder._get_retrieved_uidls()
        assert 'uidl_old' in uidls
        
        # データベースで forward_success=False を確認
        conn = sqlite3.connect(forwarder.db_path)
        cursor = conn.cursor()
        cursor.execute('SELECT forward_success FROM retrieved_mails WHERE uidl = ?', ('uidl_old',))
        row = cursor.fetchone()
        conn.close()
        assert row is not None
        assert row[0] == 0  # False
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_start_date_filter_new(self, mock_pop3, config_file):
        """start_date以降のメールは取得する"""
        # 開始日時: 2025-12-30 00:00:00 JST
        start_dt = datetime(2025, 12, 30, 0, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # 2025-12-30のメール（取得対象）
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: New Mail',
            b'Date: Tue, 30 Dec 2025 00:00:00 +0900',  # 12/30 00:00:00（境界値）
            b'',
            b'This is a new mail.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_new'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # 取得される
        assert len(new_mails) == 1
        uidl, mail_data, from_addr, subject = new_mails[0]
        assert uidl == 'uidl_new'
        assert subject == 'New Mail'
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_start_date_mixed(self, mock_pop3, config_file):
        """start_date前後のメールが混在する場合"""
        # 開始日時: 2025-12-30 12:00:00 JST
        start_dt = datetime(2025, 12, 30, 12, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_old', b'2 uidl_new1', b'3 uidl_new2'],
            0
        )
        
        # 古いメール、新しいメール2通をモック
        def retr_side_effect(msg_num):
            if msg_num == 1:  # 古いメール
                lines = [
                    b'From: old@test.jp',
                    b'Subject: Old',
                    b'Date: Tue, 30 Dec 2025 11:59:59 +0900',  # 12:00より1秒前
                    b'',
                    b'Old'
                ]
            elif msg_num == 2:  # 新しいメール1
                lines = [
                    b'From: new1@test.jp',
                    b'Subject: New1',
                    b'Date: Tue, 30 Dec 2025 12:00:00 +0900',  # 境界値
                    b'',
                    b'New1'
                ]
            else:  # 新しいメール2
                lines = [
                    b'From: new2@test.jp',
                    b'Subject: New2',
                    b'Date: Tue, 30 Dec 2025 15:00:00 +0900',
                    b'',
                    b'New2'
                ]
            return (b'+OK', lines, sum(len(line) for line in lines))
        
        pop_instance.retr.side_effect = retr_side_effect
        
        new_mails = forwarder._fetch_new_mails()
        
        # 2通が取得される（1通はスキップ）
        assert len(new_mails) == 2
        assert new_mails[0][2] == 'new1@test.jp'  # from_addr
        assert new_mails[1][2] == 'new2@test.jp'
        
        # スキップしたメールもUIDLに記録される
        uidls = forwarder._get_retrieved_uidls()
        assert 'uidl_old' in uidls
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_no_date_header(self, mock_pop3, config_file):
        """Dateヘッダーがない場合は警告して転送する"""
        start_dt = datetime(2025, 12, 30, 0, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # Dateヘッダーなし
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: No Date',
            b'',
            b'No date header.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_nodate'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # 警告して転送される
        assert len(new_mails) == 1
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_invalid_date_header(self, mock_pop3, config_file):
        """不正なDateヘッダーの場合は警告して転送する"""
        start_dt = datetime(2025, 12, 30, 0, 0, 0, tzinfo=timezone(timedelta(hours=9)))
        forwarder = MailForwarder(config_file, start_date=start_dt)
        
        # 不正なDateヘッダー
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: Invalid Date',
            b'Date: Invalid Date String',
            b'',
            b'Invalid date.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_invalid'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # 警告して転送される
        assert len(new_mails) == 1
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_without_start_date(self, mock_pop3, config_file):
        """start_date=Noneの場合は全メール取得"""
        forwarder = MailForwarder(config_file, start_date=None)
        
        # Dateヘッダーは過去の日付
        test_mail_lines = [
            b'From: sender@test.jp',
            b'Subject: Any Date',
            b'Date: Mon, 01 Jan 2020 00:00:00 +0900',
            b'',
            b'Content'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_any'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        # start_dateがないのでフィルタリングされず取得される
        assert len(new_mails) == 1
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_japanese_subject(self, mock_pop3, config_file):
        """日本語の件名を含むメールを正しく取得できる"""
        forwarder = MailForwarder(config_file)
        
        # 日本語の件名を含むテスト用メール（MIMEエンコード）
        test_mail_lines = [
            b'From: sender@test.jp',
            b'To: receiver@test.jp',
            b'Subject: =?UTF-8?B?44OG44K544OI5Lu25ZCN?=',  # "テスト件名" のBase64エンコード
            b'Date: Mon, 30 Dec 2025 12:00:00 +0900',
            b'',
            b'This is a test mail with Japanese subject.'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_jp_001'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        assert len(new_mails) == 1
        uidl, mail_data, from_addr, subject = new_mails[0]
        assert uidl == 'uidl_jp_001'
        assert from_addr == 'sender@test.jp'
        # 件名がエンコードされた状態で取得される
        assert 'UTF-8' in subject or 'テスト' in subject or '件名' in subject
    
    @patch('poplib.POP3_SSL')
    def test_fetch_new_mails_with_japanese_sender(self, mock_pop3, config_file):
        """日本語の差出人名を含むメールを正しく取得できる"""
        forwarder = MailForwarder(config_file)
        
        # 日本語の差出人名を含むテスト用メール
        test_mail_lines = [
            b'From: =?UTF-8?B?5pel5pys6Kqe?= <sender@test.jp>',  # "日本語" <sender@test.jp>
            b'To: receiver@test.jp',
            b'Subject: Test Mail',
            b'Date: Mon, 30 Dec 2025 12:00:00 +0900',
            b'',
            b'Test content'
        ]
        
        # POP3モックの設定
        pop_instance = MagicMock()
        mock_pop3.return_value = pop_instance
        pop_instance.uidl.return_value = (
            b'+OK',
            [b'1 uidl_jp_002'],
            0
        )
        pop_instance.retr.return_value = (
            b'+OK',
            test_mail_lines,
            sum(len(line) for line in test_mail_lines)
        )
        
        new_mails = forwarder._fetch_new_mails()
        
        assert len(new_mails) == 1
        uidl, mail_data, from_addr, subject = new_mails[0]
        assert uidl == 'uidl_jp_002'
        # parseaddrはメールアドレス部分のみを抽出
        assert from_addr == 'sender@test.jp'
        assert subject == 'Test Mail'
    
    @patch('smtplib.SMTP')
    def test_forward_mail_success_starttls(self, mock_smtp, config_file):
        """メール転送が成功する（STARTTLS）"""
        forwarder = MailForwarder(config_file)
        
        # SMTPモックの設定
        smtp_instance = MagicMock()
        mock_smtp.return_value = smtp_instance
        
        test_mail = b'Test mail content'
        result = forwarder._forward_mail(
            test_mail,
            'sender@test.jp',
            'Test Subject'
        )
        
        assert result is True
        smtp_instance.starttls.assert_called_once()
        smtp_instance.login.assert_called_once()
        smtp_instance.sendmail.assert_called_once()
        smtp_instance.quit.assert_called_once()
    
    @patch('smtplib.SMTP_SSL')
    def test_forward_mail_success_ssl(self, mock_smtp_ssl, config_file, temp_dir):
        """メール転送が成功する（SMTP over SSL、ポート465）"""
        # 設定を変更（ポート465）
        config_path = Path(config_file)
        with open(config_path, 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        config['smtp']['port'] = 465
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)
        
        forwarder = MailForwarder(config_file)
        
        # SMTPモックの設定
        smtp_instance = MagicMock()
        mock_smtp_ssl.return_value = smtp_instance
        
        test_mail = b'Test mail content'
        result = forwarder._forward_mail(
            test_mail,
            'sender@test.jp',
            'Test Subject'
        )
        
        assert result is True
        smtp_instance.starttls.assert_not_called()  # SSL接続なのでSTARTTLSは不要
        smtp_instance.login.assert_called_once()
        smtp_instance.sendmail.assert_called_once()
    
    @patch('smtplib.SMTP')
    def test_forward_mail_failure(self, mock_smtp, config_file):
        """メール転送が失敗する"""
        forwarder = MailForwarder(config_file)
        
        # SMTPモックで例外を発生させる
        mock_smtp.side_effect = Exception('Connection error')
        
        test_mail = b'Test mail content'
        result = forwarder._forward_mail(
            test_mail,
            'sender@test.jp',
            'Test Subject'
        )
        
        assert result is False
    
    @patch('mail_forwarder.MailForwarder._forward_mail')
    @patch('mail_forwarder.MailForwarder._fetch_new_mails')
    @patch('mail_forwarder.MailForwarder._delete_old_mails')
    def test_process_once(self, mock_delete, mock_fetch, mock_forward, config_file):
        """ワンショット処理のテスト"""
        forwarder = MailForwarder(config_file)
        
        # モックの設定
        mock_fetch.return_value = [
            ('uidl1', b'mail1', 'sender1@test.jp', 'Subject1'),
            ('uidl2', b'mail2', 'sender2@test.jp', 'Subject2')
        ]
        mock_forward.return_value = True
        
        forwarder.process_once()
        
        # 各メソッドが呼ばれることを確認
        mock_delete.assert_called_once()
        mock_fetch.assert_called_once()
        assert mock_forward.call_count == 2
        
        # 転送したメールが保存されることを確認
        uidls = forwarder._get_retrieved_uidls()
        assert 'uidl1' in uidls
        assert 'uidl2' in uidls
    
    @patch('time.sleep')
    @patch('mail_forwarder.MailForwarder._forward_mail')
    @patch('mail_forwarder.MailForwarder._fetch_new_mails')
    @patch('mail_forwarder.MailForwarder._delete_old_mails')
    def test_process_daemon(self, mock_delete, mock_fetch, mock_forward, 
                           mock_sleep, config_file):
        """デーモン処理のテスト"""
        forwarder = MailForwarder(config_file)
        
        # モックの設定
        mock_fetch.return_value = []
        
        # 1回実行したら停止するように設定
        def stop_after_first(*args):
            forwarder.running = False
        mock_sleep.side_effect = stop_after_first
        
        forwarder.process_daemon(60)
        
        # 各メソッドが呼ばれることを確認
        mock_delete.assert_called_once()
        mock_fetch.assert_called_once()
        mock_sleep.assert_called_once_with(60)
    
    @patch('time.sleep')
    @patch('mail_forwarder.MailForwarder._forward_mail')
    @patch('mail_forwarder.MailForwarder._fetch_new_mails')
    @patch('mail_forwarder.MailForwarder._delete_old_mails')
    def test_process_daemon_with_error_recovery(self, mock_delete, mock_fetch, 
                                                mock_forward, mock_sleep, config_file):
        """デーモン処理でエラーが発生しても継続する"""
        forwarder = MailForwarder(config_file)
        
        # 1回目はエラー、2回目は成功して終了
        call_count = [0]
        def fetch_side_effect():
            call_count[0] += 1
            if call_count[0] == 1:
                raise Exception('Network error')
            else:
                return []
        
        def sleep_side_effect(seconds):
            if call_count[0] >= 2:
                forwarder.running = False
        
        mock_fetch.side_effect = fetch_side_effect
        mock_sleep.side_effect = sleep_side_effect
        
        forwarder.process_daemon(60)
        
        # エラー後も継続して実行されることを確認
        assert mock_fetch.call_count == 2
        # delete_old_mailsは毎回のループで呼ばれるので2回
        assert mock_delete.call_count == 2


class TestBoundaryConditions:
    """境界値テスト"""
    
    @pytest.fixture
    def temp_dir(self):
        """テスト用の一時ディレクトリを作成"""
        temp_path = tempfile.mkdtemp()
        yield temp_path
        # ロガーのハンドラーをクローズして解放
        import logging
        logger = logging.getLogger('MailForwarder')
        handlers = logger.handlers[:]
        for handler in handlers:
            try:
                handler.close()
            except:
                pass
            logger.removeHandler(handler)
        # 少し待ってからディレクトリ削除
        time.sleep(0.1)
        try:
            shutil.rmtree(temp_path)
        except PermissionError:
            pass  # Windowsでロックされている場合は無視
    
    def test_mail_retention_days_negative(self, temp_dir):
        """mail_retention_days=-1（不正値）の場合"""
        config = {
            'pop3': {'host': 'pop.test.jp', 'port': 995, 'use_ssl': True,
                    'username': 'test', 'password': 'test'},
            'smtp': {'host': 'smtp.test.jp', 'port': 587, 'use_tls': True,
                    'username': 'test', 'password': 'test'},
            'forward': {'to_address': 'test@test.jp'},
            'mail_retention_days': -1,
            'daemon': {'interval': 300},
            'database': {'path': f'{temp_dir}/mail_uidl.db'},
            'logging': {'level': 'INFO', 'file': f'{temp_dir}/test.log', 'max_days': 30}
        }
        
        config_path = Path(temp_dir) / 'config.yaml'
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)
        
        forwarder = MailForwarder(str(config_path))
        
        # 負の値でも動作すること（古いメールを削除する基準日が未来になるので削除されない）
        forwarder._delete_old_mails()
        # エラーが発生しないことを確認（このテストが通れば成功）
    
    def test_mail_retention_days_365(self, temp_dir):
        """mail_retention_days=365（最大値想定）の場合"""
        config = {
            'pop3': {'host': 'pop.test.jp', 'port': 995, 'use_ssl': True,
                    'username': 'test', 'password': 'test'},
            'smtp': {'host': 'smtp.test.jp', 'port': 587, 'use_tls': True,
                    'username': 'test', 'password': 'test'},
            'forward': {'to_address': 'test@test.jp'},
            'mail_retention_days': 365,
            'daemon': {'interval': 300},
            'database': {'path': f'{temp_dir}/mail_uidl.db'},
            'logging': {'level': 'INFO', 'file': f'{temp_dir}/test.log', 'max_days': 30}
        }
        
        config_path = Path(temp_dir) / 'config.yaml'
        with open(config_path, 'w', encoding='utf-8') as f:
            yaml.dump(config, f)
        
        forwarder = MailForwarder(str(config_path))
        assert forwarder.config['mail_retention_days'] == 365


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
