# content.py

from flask import Blueprint, request, jsonify, render_template
from flask_jwt_extended import jwt_required, get_jwt_identity
import requests
import json

# models.py からインポート
from models import db, Vulnerability, Quiz, LearningProgress, Inquiries, User
# Slack通知用の共通関数をインポート
from config import send_slack_notification

# 1つのファイルで2つのBlueprintを定義（元の構成を維持）
content_bp = Blueprint('content_bp', __name__)
inquiry_bp = Blueprint('inquiry_bp', __name__)

# --- ページルート ---

@content_bp.route('/lesson/<int:vuln_id>')
def lesson(vuln_id):
    # db.session.get ではなく、クエリを直接発行する
    vuln = Vulnerability.query.filter_by(vuln_id=vuln_id).first()
    
    if not vuln:
        # デバッグ用にこっそりログを出す
        print(f"DEBUG: Vulnerability not found for ID {vuln_id}")
        return render_template('top.html'), 404

    # クイズデータを取得
    quiz = Quiz.query.filter_by(vuln_id=vuln_id).first()
    quiz_data = None
    if quiz:
        quiz_data = {
            "question": quiz.question_text,
            "options": [
                {"label": "A", "text": quiz.choice_a},
                {"label": "B", "text": quiz.choice_b},
                {"label": "C", "text": quiz.choice_c},
                {"label": "D", "text": quiz.choice_d},
            ],
            "answer": quiz.correct_answer,
            "explanation": quiz.explanation
        }

    # HTMLにデータを渡す
    return render_template(
        'video.html', 
        vuln_id=vuln.vuln_id,
        content_title=vuln.vuln_name,
        video_id=vuln.video_url,
        content_desc=vuln.description,
        experience_type=vuln.experience_type,
        target_keyword=vuln.target_keyword,
        success_message=vuln.success_message,
        vulnerable_code=vuln.vulnerable_code,
        fixed_code=vuln.fixed_code,          
        failure_feedback=vuln.failure_feedback if vuln.failure_feedback else "{}",
        puzzle_data=vuln.puzzle_data if vuln.puzzle_data else "[]",
        defense_puzzle_data=vuln.defense_puzzle_data if vuln.defense_puzzle_data else "[]",
        quiz_data=quiz_data
    )

@content_bp.route('/contact')
def contact(): return render_template('contact.html')

@content_bp.route("/terms")
def terms(): return render_template("terms.html")

@content_bp.route("/privacy")
def privacy(): return render_template("privacy.html")



# --- コンテンツAPI ---

@content_bp.route('/api/vulnerabilities', methods=['GET'])
def get_vulnerabilities():
    vulns = Vulnerability.query.all()
    result = []
    for v in vulns:
        result.append({
            "vuln_id": v.vuln_id,
            "vuln_name": v.vuln_name,
            "description": v.description,
            "video_url": v.video_url,
            "experience_type": v.experience_type,
            "created_at": v.created_at.strftime("%Y-%m-%d %H:%M:%S"),
            "updated_at": v.updated_at.strftime("%Y-%m-%d %H:%M:%S") if v.updated_at else None
        })
    return jsonify({"success": True, "data": result})

@content_bp.route('/api/vulnerabilities/<int:vuln_id>', methods=['GET'])
def get_vulnerability_detail(vuln_id):
    vuln = Vulnerability.query.get(vuln_id)
    if not vuln: return jsonify({'success': False, 'message': 'Not found'}), 404
    
    quiz = Quiz.query.filter_by(vuln_id=vuln_id).first()
    quiz_data = None
    if quiz:
        quiz_data = {
            "question": quiz.question_text,
            "options": [
                {"label": "A", "text": quiz.choice_a},
                {"label": "B", "text": quiz.choice_b},
                {"label": "C", "text": quiz.choice_c},
                {"label": "D", "text": quiz.choice_d},
            ],
            "answer": quiz.correct_answer,
            "explanation": quiz.explanation
        }

    return jsonify({
        'success': True, 
        'data': {
            'vuln_id': vuln.vuln_id,
            'vuln_name': vuln.vuln_name,
            'video_url': vuln.video_url, 
            'description': vuln.description,
            "vulnerable_code": vuln.vulnerable_code,
            "fixed_code": vuln.fixed_code,
            "experience_type": vuln.experience_type,
            "target_keyword": vuln.target_keyword,
            "success_message": vuln.success_message,
            "puzzle_data": vuln.puzzle_data,
            "defense_puzzle_data": vuln.defense_puzzle_data,
            "failure_feedback": vuln.failure_feedback,
            "quiz_data": quiz_data
        }
    })

@content_bp.route('/api/quizzes/<int:vuln_id>', methods=['GET'])
def get_quizzes(vuln_id):
    quizzes = Quiz.query.filter_by(vuln_id=vuln_id).all()
    quiz_list = []
    for q in quizzes:
        quiz_list.append({
            'quiz_id': q.quiz_id,
            'question_text': q.question_text,
            'choice_a': q.choice_a, 'choice_b': q.choice_b, 'choice_c': q.choice_c, 'choice_d': q.choice_d,
            'correct_answer': q.correct_answer, 'explanation': q.explanation
        })
    return jsonify({'success': True, 'quizzes': quiz_list})


# --- 進捗管理 API ---

@content_bp.route("/api/progress/update", methods=["POST"])
@jwt_required()
def update_progress():
    data = request.get_json()
    vuln_id = data.get("vuln_id")
    completed = data.get("completed")
    user_id = get_jwt_identity()
    try:
        new_status = "COMPLETED" if completed else "IN_PROGRESS"
        prog = LearningProgress.query.filter_by(user_id=user_id, vuln_id=vuln_id).first()
        if prog: prog.status = new_status
        else: db.session.add(LearningProgress(user_id=user_id, vuln_id=vuln_id, status=new_status))
        db.session.commit()
        return jsonify({"success": True, "new_status": new_status}), 200
    except Exception as e:
        return jsonify({"success": False, "message": f"Error: {str(e)}"}), 500

@content_bp.route("/api/progress/all", methods=["GET"])
@jwt_required()
def get_all_progress():
    user_id = get_jwt_identity()
    try:
        results = (
            db.session.query(Vulnerability.vuln_id, Vulnerability.vuln_name, LearningProgress.status)
            .outerjoin(LearningProgress, (Vulnerability.vuln_id == LearningProgress.vuln_id) & (LearningProgress.user_id == user_id))
            .order_by(Vulnerability.vuln_id).all()
        )
        data = []
        for vuln_id, vuln_name, status in results:
            data.append({
                "vuln_id": vuln_id, "vuln_name": vuln_name, "title": vuln_name, 
                "status": status if status else "NOT_STARTED"
            })
        return jsonify({"success": True, "data": data}), 200
    except Exception:
        return jsonify({"success": False, "message": "Error"}), 500


# --- 問い合わせ機能 (inquiry_bp) ---

@inquiry_bp.route('/api/inquiry', methods=['POST'])
@jwt_required()
def send_inquiry():
    data = request.get_json()
    user_id = get_jwt_identity()
    
    # DB保存
    new_inquiry = Inquiries(
        user_id=user_id, 
        subject=data.get('subject'), 
        message=data.get('message')
    )
    db.session.add(new_inquiry)
    db.session.commit()
    
    # Slack通知
    try:
        user = db.session.get(User, user_id)
        user_name = user.user_name if user else 'Unknown'
        
        title = "[INQUIRY] New User Inquiry"
        message = (
            f"新しい問い合わせが届きました。\n"
            f"**ユーザー名:** {user_name}\n"
            f"**件名:** {data.get('subject')}\n"
            f"**メッセージ:**\n>>> {data.get('message')}"
        )
        # config.py の共通関数を使用
        send_slack_notification(title, message, color="#3498DB")
        
    except Exception as e:
        print(f"WARN: Failed to send inquiry Slack notification: {e}") 
        
    return jsonify({"success": True, "message": "送信完了"}), 201