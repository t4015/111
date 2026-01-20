# app.py

import os
import traceback
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, jsonify, request
from flask_cors import CORS
from flask_jwt_extended import JWTManager
# ★修正: 学習画面で使う Vulnerability, Quiz を追加インポート
from models import db, TokenBlocklist, Vulnerability, Quiz

# 分割したBlueprintを読み込む
from auth import auth_bp
from admin import admin_bp
from content import content_bp, inquiry_bp

# Slack通知用
from config import send_slack_notification

from werkzeug.exceptions import HTTPException

"""
app = Flask(__name__)

# --- CORS設定 (app.py準拠) ---
CORS(app, supports_credentials=True)

# アップロードサイズ制限 (1MB)
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024

# DB設定
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_NAME = os.getenv("DB_NAME", "attacker_learn_db")

app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

# --- SECRET_KEYの設定 (app.py準拠: Fail Secure) ---
secret_key = os.environ.get("SECRET_KEY")
if not secret_key:
    raise RuntimeError("【危険】環境変数 'SECRET_KEY' が設定されていません！アプリを起動できません。")
app.config["SECRET_KEY"] = secret_key

# models.pyのdbを初期化
db.init_app(app)

# --- JWT_SECRET_KEYの設定 (app.py準拠: Fail Secure) ---
jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
if not jwt_secret_key:
    raise RuntimeError("【危険】環境変数 'JWT_SECRET_KEY' が設定されていません！アプリを起動できません。")
app.config["JWT_SECRET_KEY"] = jwt_secret_key

jwt = JWTManager(app)

# トークン失効チェック
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    with app.app_context():
        token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
    return token is not None

# --- Blueprintの登録 ---
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(content_bp)
app.register_blueprint(inquiry_bp)


# --- ページルート設定 ---

@app.route('/')
@app.route('/top')
def top(): return render_template('top.html')

# ★追加: 学習画面 (app1.pyから移植)
@app.route('/lesson/<int:vuln_id>')
def lesson(vuln_id):
    vuln = Vulnerability.query.get_or_404(vuln_id)
    quiz = Quiz.query.filter_by(vuln_id=vuln_id).first()
    quiz_data = None
    if quiz:
        quiz_data = {
            "question": quiz.question_text,
            "options": [
                {"label": "A", "text": quiz.choice_a}, {"label": "B", "text": quiz.choice_b},
                {"label": "C", "text": quiz.choice_c}, {"label": "D", "text": quiz.choice_d}
            ],
            "answer": quiz.correct_answer, "explanation": quiz.explanation
        }
    return render_template("video.html", 
        content_title=vuln.vuln_name, content_desc=vuln.description, video_id=vuln.video_url,
        vulnerable_code=vuln.vulnerable_code, fixed_code=vuln.fixed_code, experience_type=vuln.experience_type,
        target_keyword=vuln.target_keyword, success_message=vuln.success_message, puzzle_data=vuln.puzzle_data,
        defense_puzzle_data=vuln.defense_puzzle_data, failure_feedback=vuln.failure_feedback,
        quiz_data=quiz_data, vuln_id=vuln.vuln_id
    )

#@app.route("/vulnerabilities_page")
#def vulnerabilities_page(): return render_template('vulnerabilities.html')

# ★追加: パスワードリセット画面 (app1.pyから移植)
@app.route('/reset_password')
def reset_password_page(): return render_template('reset_password.html')

# 404エラーハンドラ
@app.errorhandler(404)
def not_found(e):
    return jsonify({"success": False, "message": "Page not found"}), 404

# 全体エラーハンドラ (app.py準拠: 通知有効)
@app.errorhandler(Exception)
def handle_any_exception(e):
    if isinstance(e, HTTPException):
        return e

    full_traceback = traceback.format_exc()
    title = "[CRITICAL] Uncaught Exception"
    error_message = (
        f"**エンドポイント:** `{request.method} {request.path}`\n"
        f"**エラー:** {str(e)}\n"
        f"**スタックトレース:**\n```\n{full_traceback[:1500]}\n```"
    )
    
    try:
        send_slack_notification(title, error_message, color="#FF0000")
    except Exception:
        pass

    return jsonify({"success": False, "message": "Internal Server Error"}), 500

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        
    is_debug = os.getenv("FLASK_DEBUG", "False") == "True"
    app.run(debug=is_debug, port=5000, host='0.0.0.0')

"""

def create_app(testing=False):
    app = Flask(__name__)
    
    # --- CORS & アップロード制限 ---
    CORS(app, supports_credentials=True)
    app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024
    
    # --- DB 設定 ---
    if testing:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
    else:
        DB_USER = os.getenv("DB_USER", "root")
        DB_PASSWORD = os.getenv("DB_PASSWORD", "")
        DB_HOST = os.getenv("DB_HOST", "localhost")
        DB_NAME = os.getenv("DB_NAME", "attacker_learn_db")
        app.config["SQLALCHEMY_DATABASE_URI"] = f"mysql+pymysql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}"
    
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

    # --- SECRET_KEY & JWT ---
    secret_key = os.environ.get("SECRET_KEY")
    if not secret_key:
        raise RuntimeError("SECRET_KEYが未設定です")
    app.config["SECRET_KEY"] = secret_key
    
    jwt_secret_key = os.environ.get("JWT_SECRET_KEY")
    if not jwt_secret_key:
        raise RuntimeError("JWT_SECRET_KEYが未設定です")
    app.config["JWT_SECRET_KEY"] = jwt_secret_key

    db.init_app(app)
    jwt = JWTManager(app)

    @jwt.token_in_blocklist_loader
    def check_if_token_revoked(jwt_header, jwt_payload):
        jti = jwt_payload["jti"]
        with app.app_context():
            token = db.session.query(TokenBlocklist.id).filter_by(jti=jti).scalar()
        return token is not None
    #jwt.token_in_blocklist_loader(check_if_token_revoked)
    
    # ★テスト用に追加
    app.check_if_token_revoked = check_if_token_revoked

    # --- Blueprint ---
    app.register_blueprint(auth_bp)
    app.register_blueprint(admin_bp)
    app.register_blueprint(content_bp)
    app.register_blueprint(inquiry_bp)


    # --- ルートなどはそのまま ---
    @app.route('/')
    @app.route('/top')
    def top(): return render_template('top.html')

    """
    @app.route('/lesson/<int:vuln_id>')
    def lesson(vuln_id):
        vuln = Vulnerability.query.get_or_404(vuln_id)
        quiz = Quiz.query.filter_by(vuln_id=vuln_id).first()
        quiz_data = None
        if quiz:
            quiz_data = {
                "question": quiz.question_text,
                "options": [
                    {"label": "A", "text": quiz.choice_a}, {"label": "B", "text": quiz.choice_b},
                    {"label": "C", "text": quiz.choice_c}, {"label": "D", "text": quiz.choice_d}
                ],
                "answer": quiz.correct_answer, "explanation": quiz.explanation
            }
        return render_template("video.html", 
            content_title=vuln.vuln_name, content_desc=vuln.description, video_id=vuln.video_url,
            vulnerable_code=vuln.vulnerable_code, fixed_code=vuln.fixed_code, experience_type=vuln.experience_type,
            target_keyword=vuln.target_keyword, success_message=vuln.success_message, puzzle_data=vuln.puzzle_data,
            defense_puzzle_data=vuln.defense_puzzle_data, failure_feedback=vuln.failure_feedback,
            quiz_data=quiz_data, vuln_id=vuln.vuln_id
        )
    """

    @app.route("/vulnerabilities_page")
    def vulnerabilities_page(): return render_template('vulnerabilities.html')

    @app.route('/reset_password')
    def reset_password_page(): return render_template('reset_password.html')

    @app.errorhandler(404)
    def not_found(e):
        return jsonify({"success": False, "message": "Page not found"}), 404

    @app.errorhandler(Exception)
    def handle_any_exception(e):
        if isinstance(e, HTTPException):
            return e
        full_traceback = traceback.format_exc()
        title = "[CRITICAL] Uncaught Exception"
        error_message = (
            f"**エンドポイント:** `{request.method} {request.path}`\n"
            f"**エラー:** {str(e)}\n"
            f"**スタックトレース:**\n```\n{full_traceback[:1500]}\n```"
        )
        try:
            send_slack_notification(title, error_message, color="#FF0000")
        except Exception:
            pass
        return jsonify({"success": False, "message": "Internal Server Error"}), 500

    return app

# --- 本番起動 ---
if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    is_debug = os.getenv("FLASK_DEBUG", "False") == "True"
    app.run(debug=is_debug, port=5000, host='0.0.0.0')