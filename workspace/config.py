# config.py

import os
import requests
import time

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL")

def send_slack_notification(title, message, color="#3498DB"):
    """
    指定されたメッセージをSlackに送信する共通関数
    エラー通知には #FF0000 (赤)、セキュリティイベントには #E67E22 (オレンジ) などを使用
    """
    if not SLACK_WEBHOOK_URL:
        # Webhook URLが設定されていない場合は何もしない
        return

    payload = {
        "attachments": [
            {
                "fallback": f"[{title}] {message}",
                "color": color, 
                "title": title,
                "text": message,
                "ts": int(time.time())
            }
        ]
    }
    
    try:
        # タイムアウトを短めに設定してアプリの動作を阻害しないようにする
        requests.post(SLACK_WEBHOOK_URL, json=payload, timeout=5)
    except requests.exceptions.RequestException as e:
        print(f"ERROR: Failed to send Slack notification: {e}")


