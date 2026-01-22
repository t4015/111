# conftest.py
import pytest
from flask import template_rendered
from contextlib import contextmanager
from app import create_app
from models import db, Vulnerability, Quiz

@pytest.fixture
def disable_turnstile(monkeypatch):
    monkeypatch.delenv("TURNSTILE_SECRET_KEY", raising=False)

@contextmanager
def captured_templates(app):
    recorded = []

    def record(sender, template, context, **extra):
        recorded.append((template, context))

    template_rendered.connect(record, app)
    try:
        yield recorded
    finally:
        template_rendered.disconnect(record, app)


# conftest.py
@pytest.fixture
def app():
    app = create_app(testing=True)
    
    # テスト中はSQLiteメモリDBを絶対使用
    app.config.update({
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "TESTING": True
    })

    with app.app_context():
        from models import db
        db.drop_all()
        db.create_all()
        
        # ★ここが重要：テストごとのセッション独立性を担保しつつ同期
        yield app
        
        db.session.remove()
        db.drop_all()

@pytest.fixture
def client(app):
    return app.test_client()

@pytest.fixture(autouse=True)
def setup_db(app):
    """各テストの前にセッションをクリアする"""
    with app.app_context():
        from models import db
        # 前のテストのゴミが残らないように
        db.session.expunge_all()

        
# conftest.py
@pytest.fixture
def vulnerability_with_quiz(app):
    with app.app_context():
        # 1. 脆弱性データの作成
        vuln = Vulnerability(
            vuln_name="Test Vulnerability",
            description="Test description",
            video_url="https://example.com/video.mp4",
            experience_type="TERMINAL",
            target_keyword="テスト",
            success_message="成功！",
            vulnerable_code="print('vuln')",
            fixed_code="print('fixed')",
            failure_feedback="{}",
            puzzle_data="[]",
            defense_puzzle_data="[]"
        )
        db.session.add(vuln)
        db.session.flush()  # ここでID(vuln_id)を生成させる

        # 2. クイズデータの作成
        quiz = Quiz(
            vuln_id=vuln.vuln_id,
            question_text="テスト用の質問ですか？",
            choice_a="はい",
            choice_b="いいえ",
            choice_c="わからない",
            choice_d="すべて",
            correct_answer="A",
            explanation="テストです"
        )
        db.session.add(quiz)
        
        db.session.commit()  # 確定
        
        assigned_id = vuln.vuln_id
        
        # テスト実行時にアプリ側がDBから最新情報を取得できるように
        # セッションをデタッチする
        db.session.expunge_all()
        
        yield assigned_id