import os
import urllib.request, urllib.parse

# Load environment variables from .env file (supports python-dotenv or manual parsing fallback)
try:
    from dotenv import load_dotenv
    load_dotenv(os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env"))
except ImportError:
    _env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if os.path.exists(_env_path):
        with open(_env_path, "r", encoding="utf-8") as f:
            for line in f:
                line_stripped = line.strip()
                if line_stripped and not line_stripped.startswith("#") and "=" in line_stripped:
                    try:
                        key, val = line_stripped.split("=", 1)
                        os.environ[key.strip()] = val.strip().strip('"').strip("'")
                    except Exception:
                        pass

TELEGRAM_BOT_TOKEN = os.environ.get("TELEGRAM_BOT_TOKEN", "your_bot_token")
TELEGRAM_CHAT_ID = os.environ.get("TELEGRAM_CHAT_ID", "your_chat_id")
file_name = "passwords.txt"
action = "COPIED"
severity = "CRITICAL"
location = r"E:\passwords.txt"
smb_info = ""
telegram_html = f"""
🚨 <b>CRITICAL INTRUSION DETECTED</b> 🚨

Someone has compromised a restricted honeyfile on your system!

📝 <b>Event Details:</b>
• <b>Target File:</b> <code>{file_name}</code>
• <b>Action Taken:</b> <tg-spoiler>{action}</tg-spoiler>
• <b>Severity Level:</b> <b>{severity}</b>

📂 <b>Absolute Path:</b>
<code>{location}</code>

🕵️‍♂️ <b>Network & Actor Details:</b>
<blockquote>{smb_info.strip() if smb_info.strip() else "Local (No remote SMB interaction detected)."}</blockquote>

<i>Check your system immediately!</i>
"""
try:
    telegram_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
    data = urllib.parse.urlencode({
        "chat_id": TELEGRAM_CHAT_ID,
        "text": telegram_html,
        "parse_mode": "HTML"
    }).encode("utf-8")
    req = urllib.request.Request(telegram_url, data=data)
    with urllib.request.urlopen(req) as response:
        print(response.read())
except Exception as e:
    import traceback
    traceback.print_exc()
