# admin.py

from flask import Blueprint, request, jsonify, render_template
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, jwt_required
# ★修正: RefreshTokenを追加インポート
from models import db, User, UserOTP, Vulnerability, Quiz, LearningProgress, Inquiries, RefreshToken
from argon2 import PasswordHasher
from sqlalchemy.exc import IntegrityError
import pyotp, qrcode, io, base64, csv, json, secrets
from io import StringIO
from functools import wraps

# 暗号化関数をインポート (auth.pyに定義されている前提)
from auth import encrypt_otp_secret

ph = PasswordHasher()

# Blueprintを定義
admin_bp = Blueprint('admin_bp', __name__)

# --- 管理画面ページ ---

@admin_bp.route('/admin_users')
def admin_users_page(): return render_template('admin_users.html')

@admin_bp.route('/admin_dashboard')
def admin_dashboard(): return render_template('admin_dashboard.html')

@admin_bp.route('/admin_create_user')
def admin_create_user_page(): return render_template('admin_create_user.html')


# --- 管理者権限チェック用デコレータ ---

def admin_required(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            verify_jwt_in_request()
            user_id = get_jwt_identity()
            user = db.session.get(User, user_id)
        except Exception:
            return jsonify({"success": False, "message": "認証エラー"}), 401
        if not user or user.role != "ADMIN":
            return jsonify({"success": False, "message": "権限がありません"}), 403
        return fn(*args, **kwargs)
    return wrapper




# --- 管理者機能 API ---
@admin_bp.route('/api/admin/create_user', methods=['POST'])
@jwt_required()
@admin_required
def admin_create_user():
    data = request.get_json(silent=True) or {}
    if data is None:
        return jsonify({"success": False, "message": "JSONで送信してください"}), 400


    required_fields = ["email", "password", "display_name"]
    if not all(data.get(f) for f in required_fields):
        return jsonify({"success": False, "message": "必須項目が不足しています"}), 400
    
    try:
        # パスワードハッシュ
        hashed_pw = ph.hash(data["password"])

        # ユーザー生成
        new_user = User(
            user_name=data["display_name"],
            email=data["email"],
            password_hash=hashed_pw,
            role=data.get("role", "USER")
        )

        # MFA secret生成
        mfa_secret = pyotp.random_base32()

        # 暗号化関数を使用してシークレットを暗号化 (admin1.py準拠)
        # encrypt_otp_secret はすでに base64 エンコードされた str を返す想定
        encrypted_secret = encrypt_otp_secret(mfa_secret)

        if encrypted_secret is None:
            #return jsonify({"success": False, "message": "MFAシークレットの暗号化に失敗しました"}), 500
            return jsonify({"success": False, "message": "暗号化に失敗しました"}), 500
        
        # 暗号化されたシークレットをセット
        new_user.otp = UserOTP(
            otp_secret=encrypted_secret 
        )

        db.session.add(new_user)
        db.session.commit()

        # QRコード生成（画像生成には平文のmfa_secretを使用）
        uri = pyotp.totp.TOTP(mfa_secret).provisioning_uri(
            name=data["email"],
            issuer_name="Attacker Learn"
        )

        img = qrcode.make(uri)
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        buf.seek(0)
        qr_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")

        return jsonify({
            "success": True,
            "message": "作成完了",
            "qr_code_image": f"data:image/png;base64,{qr_b64}",
        }), 201

    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "メール重複"}), 409

    except Exception as e:
        db.session.rollback()
        print(f"Server Error: {e}")
        return jsonify({"success": False, "message": "サーバーエラー"}), 500


@admin_bp.route('/api/admin/delete_vulnerability/<int:vuln_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_vulnerability(vuln_id):
    vuln = db.session.get(Vulnerability, vuln_id)
    if not vuln:
        return jsonify({"success": False, "message": "Not found"}), 404

    LearningProgress.query.filter_by(vuln_id=vuln_id).delete()
    Quiz.query.filter_by(vuln_id=vuln_id).delete()

    db.session.delete(vuln)
    db.session.commit()
    return jsonify({"success": True, "message": "削除完了"}), 200



@admin_bp.route('/api/admin/import_vulnerabilities', methods=['POST'])
@jwt_required()
@admin_required
def import_vulnerabilities():
    if 'file' not in request.files: return jsonify({"success": False, "message": "ファイルなし"}), 400
    file = request.files['file']
    filename = file.filename.lower()
    
    try:
        content = file.read().decode('utf-8')
        count = 0
        
        if filename.endswith('.json'):
            data = json.loads(content)
            if not isinstance(data, list): data = [data]
            for item in data:
                # JSONデータの整形（リストや辞書なら文字列化して保存）
                p_data = item.get('puzzle_data')
                if isinstance(p_data, (list, dict)): p_data = json.dumps(p_data, ensure_ascii=False)
                d_data = item.get('defense_puzzle_data')
                if isinstance(d_data, (list, dict)): d_data = json.dumps(d_data, ensure_ascii=False)
                
                vuln = Vulnerability(
                    vuln_name=item.get('vuln_name'), description=item.get('description'),
                    video_url=item.get('video_url'), vulnerable_code=item.get('vulnerable_code'),
                    fixed_code=item.get('fixed_code'), experience_type=item.get('experience_type', 'TERMINAL'),
                    target_keyword=item.get('target_keyword'), success_message=item.get('success_message'),
                    puzzle_data=p_data, defense_puzzle_data=d_data
                )
                db.session.add(vuln)
                count += 1

        elif filename.endswith('.csv'):
            reader = csv.reader(StringIO(content))
            next(reader, None) # ヘッダーをスキップ
            for row in reader:
                if len(row) >= 5:
                    vuln = Vulnerability(
                        vuln_name=row[0], video_url=row[1], description=row[2], 
                        vulnerable_code=row[3], fixed_code=row[4]
                    )
                    db.session.add(vuln)
                    count += 1
        else:
            return jsonify({"success": False, "message": "対応していないファイル形式です"}), 400

        db.session.commit()
        return jsonify({"success": True, "message": f"{count}件インポート完了"}), 200

    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500


# --- ユーザー管理 API ---

@admin_bp.route('/api/admin/users', methods=['GET'])
@jwt_required()
@admin_required
def get_all_users():
    users = User.query.all()
    result = []
    for u in users:
        result.append({
            "user_id": u.user_id,
            "user_name": u.user_name,
            "email": u.email,
            "role": u.role,
            "is_deleted": u.is_deleted,
            "created_at": u.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })
    return jsonify({"success": True, "data": result})

@admin_bp.route('/api/admin/users/<user_id>/toggle_freeze', methods=['POST'])
@jwt_required()
@admin_required
def toggle_user_freeze(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id == user_id:
        return jsonify({"success": False, "message": "自分自身を凍結することはできません"}), 400
    
    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    user.is_deleted = not user.is_deleted
    db.session.commit()
    status = "凍結" if user.is_deleted else "解除"
    return jsonify({"success": True, "message": f"ユーザーを{status}しました"}), 200

@admin_bp.route('/api/admin/users/<user_id>', methods=['DELETE'])
@jwt_required()
@admin_required
def delete_user(user_id):
    current_user_id = get_jwt_identity()
    if current_user_id == user_id:
        return jsonify({"success": False, "message": "自分自身を削除することはできません"}), 400

    user = db.session.get(User, user_id)
    if not user:
        return jsonify({"success": False, "message": "User not found"}), 404

    try:
        # ★修正: 関連データの完全削除 (admin1.py準拠)
        LearningProgress.query.filter_by(user_id=user_id).delete()
        Inquiries.query.filter_by(user_id=user_id).delete()
        UserOTP.query.filter_by(user_id=user_id).delete()
        RefreshToken.query.filter_by(user_id=user_id).delete()
        
        db.session.delete(user)
        db.session.commit()
        return jsonify({"success": True, "message": "削除完了"}), 200
        
    except IntegrityError:
        db.session.rollback()
        return jsonify({"success": False, "message": "関連データの削除に失敗しました"}), 500
 