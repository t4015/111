# models.py
from flask_sqlalchemy import SQLAlchemy
import uuid
from sqlalchemy.orm import relationship
from datetime import datetime

db = SQLAlchemy()

# --- データベースモデル ---

class User(db.Model):
    __tablename__ = 'users'
    user_id = db.Column(db.String(50), primary_key=True, default=lambda: str(uuid.uuid4()))
    user_name = db.Column(db.String(50), nullable=False)
    email = db.Column(db.String(255), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(10), nullable=False, default='USER')
    
    # ユーザー管理機能に必要なカラム
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())
    
    otp = db.relationship('UserOTP', back_populates='user', uselist=False, cascade="all, delete-orphan")

class UserOTP(db.Model):
    """
    MFA用シークレット管理テーブル
    【選択①: B案】セキュリティ仕様書準拠
    - otp_secret: 暗号化後の値を格納するため String(512) に拡張
    - nullable=True: MFA未設定ユーザーを許容
    """
    __tablename__ = 'user_otp'
    user_id = db.Column(db.String(50), db.ForeignKey('users.user_id', ondelete='CASCADE', onupdate='CASCADE'), primary_key=True)
    otp_secret = db.Column(db.String(512), nullable=True)
    user = db.relationship('User', back_populates='otp')

# トークンブロックリスト (ログアウト済みAccess Tokenの管理)
class TokenBlocklist(db.Model):
    __tablename__ = 'token_blocklist'
    id = db.Column(db.Integer, primary_key=True)
    jti = db.Column(db.String(36), nullable=False, index=True) # JWTの一意なID
    created_at = db.Column(db.DateTime, nullable=False)

# リフレッシュトークン管理
class RefreshToken(db.Model):
    """
    【選択②: B案】セキュリティ仕様書準拠
    - Refresh Tokenのホワイトリスト管理用テーブルを追加
    """
    __tablename__ = 'refresh_tokens'
    id = db.Column(db.Integer, primary_key=True)
    token_hash = db.Column(db.String(255), nullable=False, unique=True)
    user_id = db.Column(db.String(50), db.ForeignKey('users.user_id', ondelete='CASCADE'))
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

class PasswordResetToken(db.Model):
    """
    パスワードリセット用トークン
    【選択③: A案】機能優先
    - token: String(255) を維持（長いトークンにも対応可能）
    """
    __tablename__ = 'password_resets'
    reset_id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(255), nullable=False, index=True)
    token = db.Column(db.String(255), unique=True, nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    def is_expired(self):
        return datetime.utcnow() > self.expires_at


class Inquiries(db.Model):
    __tablename__ = 'inquiries' 
    inquiry_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(50), db.ForeignKey('users.user_id'), nullable=False) 
    subject = db.Column(db.String(255), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.Enum('UNHANDLED', 'IN_PROGRESS', 'COMPLETED'), nullable=False, default='UNHANDLED')
    admin_memo = db.Column(db.Text, nullable=True) 
    is_deleted = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow) 
    updated_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow, onupdate=datetime.utcnow) 

class Vulnerability(db.Model):
    __tablename__ = 'vulnerabilities'
    vuln_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    vuln_name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=True)
    video_url = db.Column(db.String(255), nullable=False)
    vulnerable_code = db.Column(db.Text, nullable=True)
    fixed_code = db.Column(db.Text, nullable=True)
    
    experience_type = db.Column(db.Enum('TERMINAL', 'BROWSER', 'PROXY'), default='TERMINAL')
    target_keyword = db.Column(db.Text)
    success_message = db.Column(db.Text)
    puzzle_data = db.Column(db.JSON)
    defense_puzzle_data = db.Column(db.JSON)
    failure_feedback = db.Column(db.JSON)

    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())

    quizzes = db.relationship('Quiz', backref='vulnerability', lazy=True, cascade="all, delete-orphan")

class Quiz(db.Model):
    __tablename__ = 'quizzes'
    quiz_id = db.Column(db.Integer, primary_key=True)
    vuln_id = db.Column(db.Integer, db.ForeignKey('vulnerabilities.vuln_id'), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    choice_a = db.Column(db.String(255))
    choice_b = db.Column(db.String(255))
    choice_c = db.Column(db.String(255))
    choice_d = db.Column(db.String(255))
    correct_answer = db.Column(db.String(1), nullable=False)
    explanation = db.Column(db.Text)

class LearningProgress(db.Model):
    __tablename__ = "learning_progress"
    progress_id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.String(50), db.ForeignKey("users.user_id"), nullable=False)
    vuln_id = db.Column(db.Integer, db.ForeignKey("vulnerabilities.vuln_id"), nullable=False)
    status = db.Column(db.Enum("NOT_STARTED", "IN_PROGRESS", "COMPLETED"), nullable=False, default="NOT_STARTED")
    created_at = db.Column(db.DateTime, nullable=False, server_default=db.func.current_timestamp())
    updated_at = db.Column(db.DateTime, nullable=True, server_default=db.func.current_timestamp(), onupdate=db.func.current_timestamp())