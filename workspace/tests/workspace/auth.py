# auth.py

import os
import io
import base64
import smtplib
import requests
import secrets
import hashlib
from datetime import timedelta, datetime, timezone
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from base64 import b64encode, b64decode

from flask import Blueprint, request, jsonify, render_template
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError
from sqlalchemy.exc import IntegrityError
import pyotp
import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from flask_jwt_extended import verify_jwt_in_request


from flask_jwt_extended import (
    create_access_token,
    get_jwt_identity,
    get_jwt,
    jwt_required
)

# models.py からインポート (RefreshTokenを追加)
from models import db, User, UserOTP, TokenBlocklist, PasswordResetToken, RefreshToken

ph = PasswordHasher()


#テストのために追加
def verify_password(hash, password):
    return ph.verify(hash, password)


auth_bp = Blueprint('auth_bp', __name__)

# 環境変数の取得
TURNSTILE_SECRET_KEY = os.getenv("TURNSTILE_SECRET_KEY")
if not TURNSTILE_SECRET_KEY or TURNSTILE_SECRET_KEY.startswith("0x"):
    print("WARNING: Turnstile secret key is not properly configured.")

ENCRYPTION_KEY = os.getenv("MFA_ENCRYPTION_KEY")

if ENCRYPTION_KEY is None:
    print("警告: MFA_ENCRYPTION_KEYが設定されていません。")

# --- ページルート ---

@auth_bp.route('/login')
def login(): return render_template('login.html')

@auth_bp.route('/register')
def register(): return render_template('register.html')

@auth_bp.route('/mypage')
def mypage(): return render_template('mypage.html')

@auth_bp.route('/forgot_password')
def forgot_password(): return render_template('forgot_password.html')

# --- ヘルパー関数: 暗号化/復号 (A案ベース) ---

#def get_encryption_key():
#   if not ENCRYPTION_KEY:
"""環境変数から32バイトの鍵を取得・デコードする"""
def get_encryption_key():
    key = os.getenv("MFA_ENCRYPTION_KEY")
    if not key:
        return None
    try:
        #return b64decode(ENCRYPTION_KEY)
        return b64decode(key)
    except Exception as e:
        print(f"Encryption Key Error: {e}")
        return None

def encrypt_otp_secret(secret_base32: str) -> str:
    """TOTPシークレットを暗号化してBase64文字列で返す"""
    key = get_encryption_key()
    #if not key:
    #    return secret_base32
    if not key:
       return None

    try:
        aesgcm = AESGCM(key)
        data = secret_base32.encode("utf-8")
        nonce = os.urandom(12)
        ciphertext = aesgcm.encrypt(nonce, data, None)
        return b64encode(nonce + ciphertext).decode("utf-8")
    except Exception as e:
        print(f"Encryption Error: {e}")
        return None

def decrypt_otp_secret(encrypted_b64: str) -> str:
    """暗号化されたBase64文字列を復号して返す"""
    key = get_encryption_key()
    if not key:
        return encrypted_b64

    try:
        # パディング補完
        missing_padding = len(encrypted_b64) % 4
        if missing_padding:
            encrypted_b64 += '=' * (4 - missing_padding)

        encrypted_bytes = b64decode(encrypted_b64)
        nonce = encrypted_bytes[:12]
        ct = encrypted_bytes[12:]

        aesgcm = AESGCM(key)
        plain = aesgcm.decrypt(nonce, ct, None)
        return plain.decode("utf-8")
    except Exception as e:
        print(f"Decryption Error: {e}")
        return None

# --- ヘルパー関数: その他 ---

def check_turnstile(token):
    if not TURNSTILE_SECRET_KEY: 
        return True 
    if not token: 
        return False
    try:
        resp = requests.post(
            "https://challenges.cloudflare.com/turnstile/v0/siteverify", 
            data={'secret': TURNSTILE_SECRET_KEY, 'response': token}
        )
        return resp.json().get('success', False)
    except Exception as e:
        print(f"Turnstile Error: {e}")
        return False

def send_password_reset_email(to_email, reset_link):
    """【選択①: A案】SMTPを使用してメールを送信"""
    smtp_server = os.getenv("MAIL_SERVER")
    smtp_port = int(os.getenv("MAIL_PORT", 587))
    smtp_user = os.getenv("MAIL_USERNAME")
    smtp_password = os.getenv("MAIL_PASSWORD")
    sender_email = os.getenv("MAIL_SENDER")

    if not all([smtp_server, smtp_user, smtp_password, sender_email]):
        # 設定がない場合はログに出力して成功扱いにする（開発用）
        print(f"!!! Email config missing. Link for {to_email}: {reset_link} !!!")
        return True

    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = to_email
    msg['Subject'] = "【Webセキュリティ学習】パスワードリセットのお知らせ"

    body = f"""
    パスワードリセットのリクエストを受け付けました。
    以下のリンクをクリックして、新しいパスワードを設定してください。

    {reset_link}

    ※このリンクは有効期限があります。
    """
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.starttls()
        server.login(smtp_user, smtp_password)
        server.send_message(msg)
        server.quit()
        print(f"Email sent to {to_email}")
        return True
    except Exception as e:
        print(f"Email send error: {e}")
        return False

# --- ヘルパー関数: リフレッシュトークン (B案から移植) ---

def create_and_store_refresh_token(user_id, expires_in_days=30):
    refresh_token = secrets.token_urlsafe(64)
    # DBにはハッシュ値を保存（ホワイトリスト）
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    expires_at = datetime.utcnow() + timedelta(days=expires_in_days)
    
    db.session.add(RefreshToken(token_hash=token_hash, user_id=user_id, expires_at=expires_at))
    db.session.commit()
    return refresh_token

def verify_refresh_token(refresh_token, user_id):
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    entry = RefreshToken.query.filter_by(token_hash=token_hash, user_id=user_id).first()
    if not entry: return False, "Token not found"
    if entry.expires_at < datetime.utcnow(): return False, "Token expired"
    return True, entry

def delete_refresh_token(refresh_token, user_id):
    token_hash = hashlib.sha256(refresh_token.encode()).hexdigest()
    entry = RefreshToken.query.filter_by(token_hash=token_hash, user_id=user_id).first()
    if entry:
        db.session.delete(entry)
        db.session.commit()
        return True
    return False


# --- API エンドポイント ---

@auth_bp.route('/api/logout', methods=['DELETE'])
@jwt_required()
def logout():
    jti = get_jwt()["jti"]
    now = datetime.now(timezone.utc)
    # Access Tokenをブラックリストへ
    db.session.add(TokenBlocklist(jti=jti, created_at=now))
    
    # リフレッシュトークンも送られてきたら無効化（ホワイトリストから削除）
    data = request.get_json() or {}
    refresh_token = data.get("refresh_token")
    if refresh_token:
        delete_refresh_token(refresh_token, get_jwt_identity())

    db.session.commit()
    return jsonify(msg="ログアウトしました")

@auth_bp.route('/api/register', methods=['POST'])
def register_user():
    data = request.get_json() or {}

    if not check_turnstile(data.get('cf-turnstile-response')):
        return jsonify({"success": False, "message": "BOT検出"}), 403

    try:
        hashed_password = ph.hash(data.get('password'))

        new_user = User(
            user_name=data.get('display_name'),
            email=data.get('email'),
            password_hash=hashed_password,
            role='USER'
        )
        db.session.add(new_user)
        db.session.flush() # user_idを確定

        # MFAシークレット生成と暗号化
        mfa_secret = pyotp.random_base32()
        encrypted_secret = encrypt_otp_secret(mfa_secret)

        if encrypted_secret is None:
             raise Exception("MFA encryption failed")

        user_otp = UserOTP(
            user_id=new_user.user_id,
            otp_secret=encrypted_secret
        )
        db.session.add(user_otp)
        db.session.commit()
        
        # QRコード生成
        uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
            name=data.get('email'), 
            issuer_name="Attacker Learn"
        )
        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        qr_b64 = base64.b64encode(buf.getvalue()).decode('utf-8')

        return jsonify({
            "success": True, 
            "message": "登録完了", 
            "qr_code_image": f"data:image/png;base64,{qr_b64}"
        }), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "メールアドレス重複"}), 409
    except Exception as e:
        db.session.rollback()
        print(f"Register Error: {e}")
        return jsonify({"success": False, "message": "エラー発生"}), 500

@auth_bp.route('/api/login', methods=['POST'])
def login_user():
    """【選択③: 統合案】MFA検証(A) + リフレッシュトークン発行(B)"""
    data = request.get_json() or {}
    if not check_turnstile(data.get('cf-turnstile-response')): 
        return jsonify({"success": False, "message": "BOT検出"}), 403
    
    user = User.query.filter_by(email=data.get('email'), is_deleted=False).first()
    if not user: return jsonify({"success": False, "message": "認証失敗"}), 401
    
    try:
        #ph.verify(user.password_hash, data.get('password'))
        verify_password(user.password_hash, data.get('password'))

        # --- A案のMFA検証ロジック ---
        user_otp = UserOTP.query.get(user.user_id)
        if user_otp and user_otp.otp_secret:
            secret = decrypt_otp_secret(user_otp.otp_secret)
            if secret:
                totp = pyotp.TOTP(secret)
                if not totp.verify(data.get('otp_code')):
                    return jsonify({"success": False, "message": "OTPエラー"}), 401
            else:
                return jsonify({"success": False, "message": "MFAエラー"}), 500
        
        # --- B案のリフレッシュトークン発行 ---
        access_token = create_access_token(identity=user.user_id, expires_delta=timedelta(hours=1))
        refresh_token = create_and_store_refresh_token(user.user_id)
        
        return jsonify({
            "success": True, 
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200

    except VerifyMismatchError:
        return jsonify({"success": False, "message": "認証失敗"}), 401

@auth_bp.route('/api/refresh', methods=['POST'])
def refresh_token_route():
    """リフレッシュトークンを使ってAccess Tokenを再発行する"""
    data = request.get_json() or {}
    user_id = data.get("user_id") 
    refresh_token = data.get("refresh_token")
    
    if not user_id or not refresh_token:
        return jsonify({"success": False, "message": "Missing tokens"}), 400

    valid, entry_or_msg = verify_refresh_token(refresh_token, user_id)
    if not valid:
        return jsonify({"success": False, "message": entry_or_msg}), 401

    access_token = create_access_token(identity=user_id, expires_delta=timedelta(hours=1))
    return jsonify({"success": True, "access_token": access_token})

@auth_bp.route('/api/me', methods=['GET'])
@jwt_required()
def get_my_profile():
    user_id = get_jwt_identity()
    user = User.query.filter_by(user_id=user_id).first()
    if not user: return jsonify({"success": False, "message": "User not found"}), 404
    
    return jsonify({
        "success": True, 
        "user": {
            "email": user.email, 
            "display_name": user.user_name, 
            "role": user.role,
            "created_at": user.created_at.strftime('%Y/%m/%d')
        }
    }), 200

"""
@auth_bp.route('/api/change_password', methods=['POST'])
@jwt_required()
def change_password():
    data = request.get_json()
    user_id = get_jwt_identity()
    user = User.query.filter_by(user_id=user_id).first()
    try:
        #ph.verify(user.password_hash, data.get('current_password'))
        verify_password(user.password_hash, data.get('current_password'))

        if len(data.get('new_password')) < 8: return jsonify({'success': False, 'message': 'パスワードは8文字以上'}), 400
        user.password_hash = ph.hash(data.get('new_password'))
        db.session.commit()
        return jsonify({"success": True, "message": "パスワード更新完了"}), 200
    except VerifyMismatchError:
        return jsonify({"success": False, "message": "現在のパスワードが違います"}), 401

"""        
@auth_bp.route("/api/change_password", methods=["POST"])
@jwt_required()
def change_password():
    data = request.get_json() or {}

    current_password = data.get("current_password")
    new_password = data.get("new_password")

    # 入力チェック
    if not current_password or not new_password:
        return jsonify({
            "success": False,
            "message": "入力値が不正です"
        }), 400

    # 新パスワード長チェック（★ここが先）
    if len(new_password) < 8:
        return jsonify({
            "success": False,
            "message": "パスワードは8文字以上"
        }), 400

    # JWT
    user_id = get_jwt_identity()

    user = User.query.filter_by(
        user_id=user_id,
        is_deleted=False
    ).first()

    if not user:
        return jsonify({
            "success": False,
            "message": "ユーザーが存在しません"
        }), 404

    # 現在パスワード検証
    try:
        verify_password(user.password_hash, current_password)
    except Exception:
        return jsonify({
            "success": False,
            "message": "現在のパスワードが違います"
        }), 401

    # 更新
    user.password_hash = hash_password(new_password)
    db.session.commit()

    return jsonify({
        "success": True,
        "message": "パスワード更新完了"
    }), 200


@auth_bp.route('/api/update_profile', methods=['POST'])
@jwt_required()
def update_profile():
    data = request.get_json()
    name = data.get('display_name', '').strip()
    if not name or len(name) > 255: return jsonify({'success': False, 'message': '不正な名前です'}), 400
    user = User.query.filter_by(user_id=get_jwt_identity()).first()
    user.user_name = name
    db.session.commit()
    return jsonify({'success': True, 'message': '更新完了'}), 200
"""
@auth_bp.route('/api/request_password_reset', methods=['POST'])
def request_password_reset():
    #【選択②: B案+A案】トークンはハッシュ保存(B)、メールはSMTP送信(A)
    #data = request.get_json()
    #if not check_turnstile(data.get('cf-turnstile-response')):
    #    return jsonify({"success": False, "message": "BOT検出"}), 403
    data = request.get_json(silent=True) or {}


    if not check_turnstile(data.get('cf-turnstile-response')):
        return jsonify({"success": False, "message": "BOT検出"}), 403

    
    email = data.get('email')
    user = User.query.filter_by(email=email, is_deleted=False).first()
    
    if user:
        PasswordResetToken.query.filter_by(email=email).delete()
        
        # B案: 48バイトのランダムトークン生成 -> ハッシュ化して保存
        raw_token = secrets.token_urlsafe(48)
        token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expires_at = datetime.utcnow() + timedelta(minutes=15)
        
        new_token = PasswordResetToken(email=email, token=token_hash, expires_at=expires_at)
        db.session.add(new_token)
        db.session.commit()
        
        # A案: メール送信 (URLには raw_token を埋め込む)
        # ※ request.host_url は "http://localhost:5000/" のように末尾スラッシュ付き
        reset_link = f"{request.host_url}reset_password?token={raw_token}"
        send_password_reset_email(email, reset_link)
        
    return jsonify({"success": True, "message": "リンクを送信しました"}), 200
"""

@auth_bp.route("/api/request_password_reset", methods=["POST"])
def request_password_reset():
    data = request.get_json() or {}

    email = data.get("email")
    turnstile_token = data.get("cf-turnstile-response")

    # Turnstile チェック
    if not check_turnstile(turnstile_token):
        return jsonify({
            "success": False,
            "message": "認証に失敗しました"
        }), 403

    if not email:
        return jsonify({
            "success": True,
            "message": "パスワードリセット用のメールを送信しました"
        }), 200

    user = User.query.filter_by(
        email=email,
        is_deleted=False
    ).first()

    # 情報漏洩防止
    if not user:
        return jsonify({
            "success": True,
            "message": "パスワードリセット用のメールを送信しました"
        }), 200

    # 既存トークン削除
    PasswordResetToken.query.filter_by(user_id=user.user_id).delete()

    # 新トークン作成
    token = PasswordResetToken.create(user.user_id)
    db.session.add(token)
    db.session.commit()

    # メール送信
    send_password_reset_email(user.email, token.token)

    return jsonify({
        "success": True,
        "message": "パスワードリセット用のメールを送信しました"
    }), 200



@auth_bp.route('/api/reset_password', methods=['POST'])
def exec_reset_password():
    """【選択②: B案】受け取ったトークンをハッシュ化して照合"""
    data = request.get_json() or {}
    raw_token = data.get('reset_token')
    
    if not raw_token:
        return jsonify({"success": False, "message": "トークンが必要です"}), 400

    # 受け取ったトークンをハッシュ化してDB検索
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    token_rec = PasswordResetToken.query.filter_by(token=token_hash).first()
    
    if not token_rec or token_rec.is_expired(): 
        return jsonify({"success": False, "message": "無効または期限切れのトークン"}), 400
        
    user = User.query.filter_by(email=token_rec.email).first()
    
    if user:
        user.password_hash = ph.hash(data.get('new_password'))
        db.session.delete(token_rec)
        db.session.commit()
        return jsonify({"success": True, "message": "パスワード更新完了"}), 200
        
    return jsonify({"success": False, "message": "ユーザー不明"}), 404

@auth_bp.route('/api/update_email', methods=['POST'])
@jwt_required()
def update_email():
    data = request.get_json()
    new_email = data.get('new_email', '').strip()
    current_password = data.get('current_password', '')
    
    if not new_email or '@' not in new_email:
        return jsonify({'success': False, 'message': '有効なメールアドレスを入力してください'}), 400
    if not current_password:
        return jsonify({'success': False, 'message': 'パスワードが必要です'}), 400

    user_id = get_jwt_identity()
    user = User.query.filter_by(user_id=user_id).first()
    
    try:
        #ph.verify(user.password_hash, current_password)
        verify_password(user.password_hash, current_password)
    except VerifyMismatchError:
        return jsonify({'success': False, 'message': 'パスワードが間違っています'}), 401

    try:
        user.email = new_email
        db.session.commit()
        return jsonify({'success': True, 'message': '更新完了'}), 200
    except IntegrityError:
        db.session.rollback()
        return jsonify({'success': False, 'message': '既に使用されているアドレスです'}), 409
    except Exception as e:
        db.session.rollback()
        return jsonify({'success': False, 'message': 'エラー発生'}), 500
    



#test用
# auth.py

ph = PasswordHasher()

def hash_password(password: str) -> str:
    """パスワードハッシュを返すラッパー関数"""
    return ph.hash(password)