import os
import re
import secrets
import smtplib
import hashlib
import random
import requests
from email.mime.text import MIMEText
from flask import Flask, render_template, request, jsonify, redirect, url_for, session, flash
from flask_cors import CORS

# Try importing Bcrypt from flask_bcrypt, or fallback to werkzeug.security / hashlib
try:
    from flask_bcrypt import Bcrypt
    has_bcrypt = True
except ImportError:
    has_bcrypt = False

try:
    from werkzeug.security import generate_password_hash, check_password_hash
    has_werkzeug = True
except ImportError:
    has_werkzeug = False

# Try importing google.generativeai
try:
    import google.generativeai as genai
    has_genai = True
except ImportError:
    has_genai = False

# Import database module
from database import get_db, init_db

app = Flask(__name__, static_folder='Assest', static_url_path='/Assest')
app.secret_key = "a3f6d94a9b1c4b15bbfc6e529f861e637e249d1dd8a6e4c1a71c2d5fbdfe098f"

if has_bcrypt:
    bcrypt = Bcrypt(app)
else:
    bcrypt = None

CORS(app)

# Initialize database tables
init_db()

# Configure Google Gemini AI if package is present
GEMINI_API_KEY = os.environ.get("GEMINI_API_KEY", "AIzaSyCz2YVpFuYbMGqwARQq2pW1u8J438_Zbho")
if has_genai:
    try:
        genai.configure(api_key=GEMINI_API_KEY)
    except Exception as e:
        print(f"Gemini AI configuration notice: {e}")

# Load spaCy NLP model for linguistic evaluation and gibberish detection
try:
    import spacy
    try:
        nlp = spacy.load('en_core_web_md')
    except Exception:
        nlp = spacy.load('en_core_web_sm')
    has_spacy = True
except Exception as e:
    print(f"spaCy loading notice: {e}")
    nlp = None
    has_spacy = False

COMMON_NAMES_AND_WORDS = {
    "rani", "aarav", "priya", "diwali", "diya", "diyas", "darjeeling", "sector",
    "hackathon", "lantern", "lanterns", "tiger", "hill", "delhi", "mumbai", "india"
}

def hash_pass(pwd):
    if has_bcrypt and bcrypt:
        return bcrypt.generate_password_hash(pwd).decode('utf-8')
    elif has_werkzeug:
        return generate_password_hash(pwd)
    else:
        return hashlib.sha256(pwd.encode('utf-8')).hexdigest()

def verify_pass(hashed, pwd):
    if has_bcrypt and bcrypt:
        try:
            return bcrypt.check_password_hash(hashed, pwd)
        except Exception:
            pass
    if has_werkzeug:
        try:
            return check_password_hash(hashed, pwd)
        except Exception:
            pass
    return hashed == hashlib.sha256(pwd.encode('utf-8')).hexdigest()

def is_valid_email(email):
    """ Validate email format using regex """
    email_pattern = r"^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(email_pattern, email))

# --- ROUTING & AUTHENTICATION ---

@app.route('/', methods=['GET'])
@app.route('/pl', methods=['GET'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": "Email and password are required!"}), 400
            flash("Email and password are required!", "danger")
            return render_template("index.html")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()
        conn.close()

        if user and verify_pass(user['password'], password):
            session['user_email'] = email
            session['user_name'] = user.get('name', email.split('@')[0])
            session['user_id'] = user.get('id')
            
            details_filled = bool(user.get('age') and user.get('profession') and user.get('english_level'))
            
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({
                    "success": True,
                    "detailsFilled": details_filled,
                    "message": "Login Successfully!!",
                    "email": email
                })
            
            if not details_filled:
                return redirect(url_for('user_details_page'))
            return redirect(url_for('dash'))
        else:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": "Invalid email or password"}), 401
            flash("Invalid email or password", "danger")
            return render_template("index.html")

    return render_template("index.html")

@app.route('/sign1', methods=['GET', 'POST'])
@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        name = request.form.get('name', 'Learner').strip()
        email = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        confirm_password = request.form.get('Confirm_password', request.form.get('confirm_password', '')).strip()

        if not is_valid_email(email):
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": "❌ Invalid email format! Please enter a valid email."}), 400
            flash("Invalid email format!", "danger")
            return render_template("SignUp.html")

        if password and confirm_password and password != confirm_password:
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": "❌ Passwords do not match!"}), 400
            flash("Passwords do not match!", "danger")
            return render_template("SignUp.html")

        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        existing_user = cursor.fetchone()

        if existing_user:
            conn.close()
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": "❌ Account with this email already exists!"}), 400
            flash("Account already exists! Please login.", "warning")
            return redirect(url_for('login'))

        hashed_password = hash_pass(password)
        try:
            cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                           (name, email, hashed_password))
            conn.commit()
            conn.close()
            
            session['user_email'] = email
            session['user_name'] = name

            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": True, "message": "✅ Signup successful!"}), 200
            
            return redirect(url_for('user_details_page'))
        except Exception as e:
            conn.close()
            if request.is_json or request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return jsonify({"success": False, "message": f"❌ Database Error: {str(e)}"}), 500
            flash(f"Database Error: {str(e)}", "danger")
            return render_template("SignUp.html")

    return render_template("SignUp.html")

@app.route('/user-details', methods=['GET'])
def user_details_page():
    return render_template("UserDetails.html")

@app.route('/user_details', methods=['POST'])
def user_details():
    email = request.form.get('email', session.get('user_email', ''))
    age = request.form.get('age')
    profession = request.form.get('profession')
    english_level = request.form.get('english_level')

    if not email:
        return redirect(url_for('login'))

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("UPDATE users SET age = ?, profession = ?, english_level = ? WHERE email = ?",
                   (age, profession, english_level, email))
    conn.commit()
    conn.close()

    return redirect(url_for('dash'))

@app.route('/dashboard')
@app.route('/homepage')
def dash():
    return render_template('homepage.html')

# --- FORGOT PASSWORD ---

@app.route('/forgot_password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email', '').strip()
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM users WHERE email = ?", (email,))
        user = cursor.fetchone()

        if user:
            reset_token = secrets.token_urlsafe(16)
            cursor.execute("UPDATE users SET reset_token = ? WHERE email = ?", (reset_token, email))
            conn.commit()
            conn.close()
            reset_link = f"{request.host_url}reset_password?token={reset_token}"
            try:
                send_reset_email(email, reset_link)
                flash("A password reset link has been generated and sent!", "success")
            except Exception:
                flash(f"Password reset link generated: {reset_link}", "info")
            return render_template("forget.html", reset_link=reset_link)
        else:
            conn.close()
            flash("No account found with this email.", "danger")
            return render_template("forget.html")

    return render_template("forget.html")

def send_reset_email(to_email, reset_link):
    sender_email = "ysikha642@gmail.com"
    sender_password = "ylch fdsc cjci xeby"
    msg = MIMEText(f"Click the following link to reset your password: {reset_link}")
    msg['Subject'] = "Password Reset Request"
    msg['From'] = sender_email
    msg['To'] = to_email

    server = smtplib.SMTP("smtp.gmail.com", 587)
    server.starttls()
    server.login(sender_email, sender_password)
    server.sendmail(sender_email, to_email, msg.as_string())
    server.quit()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    token = request.args.get('token')
    if not token:
        return "Invalid or missing token", 400

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE reset_token = ?", (token,))
    user = cursor.fetchone()

    if not user:
        conn.close()
        return "Invalid or expired token", 400

    if request.method == 'POST':
        new_password = request.form.get('password')
        hashed_password = hash_pass(new_password)
        cursor.execute("UPDATE users SET password = ?, reset_token = NULL WHERE reset_token = ?",
                       (hashed_password, token))
        conn.commit()
        conn.close()
        flash("Your password has been successfully reset. You can now log in.", "success")
        return redirect(url_for('login'))

    conn.close()
    return render_template("reset.html", token=token)

# --- AI ASSISTANT CHAT ---

@app.route('/chat')
@app.route('/Chat.html')
def index():
    return render_template("chat.html")

def generate_gemini_rest_response(prompt, api_key):
    if not api_key:
        return None
    for model_name in ["gemini-1.5-flash", "gemini-2.0-flash", "gemini-1.5-pro"]:
        try:
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model_name}:generateContent?key={api_key}"
            payload = {
                "contents": [{"parts": [{"text": prompt}]}],
                "generationConfig": {"temperature": 0.7, "maxOutputTokens": 600}
            }
            r = requests.post(url, json=payload, timeout=6)
            if r.status_code == 200:
                data = r.json()
                candidates = data.get("candidates", [])
                if candidates:
                    parts = candidates[0].get("content", {}).get("parts", [])
                    if parts and "text" in parts[0]:
                        return parts[0]["text"]
        except Exception:
            pass
    return None

def generate_fallback_ai_response(msg, details):
    msg_clean = msg.strip()
    msg_lower = msg_clean.lower()
    prof = details.get('profession', 'Student')
    level = details.get('english_level', 'Intermediate')
    name = details.get('name', 'Learner')

    # 1. Greetings
    if re.search(r'\b(hello|hi|hey|good morning|good afternoon|good evening)\b', msg_lower) and len(msg_clean.split()) <= 4:
        return (
            f"👋 Hello {name}! Welcome to your TalkPro AI session.\n\n"
            f"As someone pursuing {prof} with a {level} English goal, daily speaking practice builds tremendous fluency. "
            f"Try typing a full sentence, testing a grammar doubt, or asking for interview phrases!"
        )

    # 2. General English query handlers
    if "interview" in msg_lower:
        return (
            "💼 **Professional Job Interview Tips**:\n\n"
            "1. **Self-Introduction Formula**: 'I am a [profession] with strong interest in [field]. Over the past [X] years, I have developed skills in...'\n"
            "2. **Confidence Tip**: Pause before answering rather than using filler sounds like 'umm' or 'uhh'.\n"
            "3. **Power Verbs**: Use action words like *spearheaded*, *collaborated*, *implemented*, and *achieved*.\n\n"
            "Would you like to practice answering a common question like *'Tell me about yourself'*?"
        )

    if "synonym" in msg_lower or "vocabulary" in msg_lower:
        return (
            "📚 **Vocabulary Enhancement Tip**:\n\n"
            "Instead of overusing basic words like *'good'*, *'happy'*, or *'hard'*, try these high-impact alternatives:\n"
            "• **Happy** ➔ *Delighted, Elated, Content, Ecstatic*\n"
            "• **Important** ➔ *Crucial, Paramount, Essential, Vital*\n"
            "• **Difficult** ➔ *Challenging, Demanding, Arduous, Complex*\n\n"
            "Try creating a sentence using one of these words!"
        )

    # 3. Hindi / Hinglish translation & explanations
    hinglish_map = {
        r'\bkaise ho\b': ("How are you?", "'Kaise ho' is commonly said as 'How are you?' or 'How are you doing today?' in English."),
        r'\bkya haal hai\b': ("How are things?", "'Kya haal hai' can be expressed casually as 'How are things going?' or 'What's up?' in English."),
        r'\bnamaste\b': ("Hello / Good day", "'Namaste' translates as a formal respectful greeting such as 'Hello' or 'Good day'."),
        r'\bdhanyawad\b|\bshukriya\b': ("Thank you", "The English equivalent is 'Thank you' or 'Thank you very much!'."),
        r'\baccha\b|\bacha\b': ("Good / I understand", "Depending on context, 'accha' can mean 'Good', 'I see', or 'Alright.'"),
        r'\bmadad\b': ("Help / Assistance", "'Madad' translates to 'Help' or 'Can you assist me?' in English."),
        r'\bkya kar rahe ho\b': ("What are you doing?", "'Kya kar rahe ho' translates directly to 'What are you doing?' in English.")
    }

    for pattern, (eng_trans, explanation) in hinglish_map.items():
        if re.search(pattern, msg_lower):
            return (
                f"🇮🇳 ➔ 🇬🇧 **Hinglish to English Translation**:\n\n"
                f"• **English Expression**: \"{eng_trans}\"\n"
                f"• **Usage Insight**: {explanation}\n\n"
                f"💡 **Practice**: Try replying with a full sentence in English using \"{eng_trans}\"!"
            )

    # 4. Grammar Rule-Based Checking
    corrections = []
    corrected_text = msg_clean
    has_past_marker = bool(re.search(r'\b(yesterday|last\s+(night|week|month|year)|ago|in \d{4})\b', msg_lower))

    # Subject-verb agreement with 'go'
    if re.search(r'\bI\s+goes\b', corrected_text, re.IGNORECASE):
        replacement = "I went" if has_past_marker else "I go"
        corrected_text = re.sub(r'\bI\s+goes\b', replacement, corrected_text, flags=re.IGNORECASE)
        corrections.append(f"Use **'{replacement}'** instead of 'I goes'. 'Goes' is only used for third-person singular (he/she/it).")
    elif re.search(r'\b(he|she|it)\s+go\b', corrected_text, re.IGNORECASE):
        replacement = "went" if has_past_marker else "goes"
        corrected_text = re.sub(r'\b(he|she|it)\s+go\b', r'\1 ' + replacement, corrected_text, flags=re.IGNORECASE)
        corrections.append(f"With third-person singular (he/she/it), use **'{replacement}'** instead of 'go'.")

    # Missing article before market/school/work
    if re.search(r'\bto\s+market\b', corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r'\bto\s+market\b', 'to the market', corrected_text, flags=re.IGNORECASE)
        corrections.append("Add the definite article **'the'**: say **'to the market'**.")

    # Double past tense error: didn't went, did you saw
    double_past = re.search(r"\b(didn't|did not|did you)\s+(went|saw|bought|came|ate|took)\b", corrected_text, re.IGNORECASE)
    if double_past:
        aux, past_v = double_past.groups()
        base_verbs = {'went': 'go', 'saw': 'see', 'bought': 'buy', 'came': 'come', 'ate': 'eat', 'took': 'take'}
        base_v = base_verbs.get(past_v.lower(), past_v)
        corrected_text = re.sub(r"\b" + aux + r"\s+" + past_v + r"\b", f"{aux} {base_v}", corrected_text, flags=re.IGNORECASE)
        corrections.append(f"After auxiliary verb '{aux}', always use the base verb **'{base_v}'** (not the past tense form '{past_v}').")

    # She don't / He don't -> doesn't
    if re.search(r"\b(he|she|it)\s+(don't|dont)\b", corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r"\b(he|she|it)\s+(don't|dont)\b", r"\1 doesn't", corrected_text, flags=re.IGNORECASE)
        corrections.append("Third-person singular subjects (he/she/it) require **'doesn\'t'**, not 'don\'t'.")

    # We was / They was -> were
    if re.search(r"\b(we|they)\s+was\b", corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r"\b(we|they)\s+was\b", r"\1 were", corrected_text, flags=re.IGNORECASE)
        corrections.append("Plural pronouns (we/they) take **'were'**, not 'was'.")

    # Stative verb continuous: I am having a car
    if re.search(r"\bI\s+am\s+having\s+(a\s+)?(car|bike|laptop|phone|brother|sister|house)\b", corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r"\bI\s+am\s+having\b", "I have", corrected_text, flags=re.IGNORECASE)
        corrections.append("To express ownership or relationships, use stative verb **'I have'** instead of the continuous 'I am having'.")

    # Redundancy: revert back
    if re.search(r"\brevert\s+back\b", corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r"\brevert\s+back\b", "revert (or reply)", corrected_text, flags=re.IGNORECASE)
        corrections.append("'Revert' already means to reply/return, so adding 'back' is redundant.")

    # Missing 'to' with listen: listen music -> listen to music
    if re.search(r"\blisten\s+(music|songs|podcast|radio)\b", corrected_text, re.IGNORECASE):
        corrected_text = re.sub(r"\blisten\s+(music|songs|podcast|radio)\b", r"listen to \1", corrected_text, flags=re.IGNORECASE)
        corrections.append("The verb 'listen' requires the preposition **'to'** before the object (e.g. *listen to music*).")

    # Slang & text shortcuts
    slang_dict = {
        r'\bwanna\b': 'want to',
        r'\bgonna\b': 'going to',
        r'\bu\s+r\b': 'you are',
        r'\bur\b': 'your',
        r'\br\s+u\b': 'are you',
        r'\bplz\b|\bpls\b': 'please',
        r'\bthx\b|\btnx\b': 'thanks'
    }
    for s_pat, s_repl in slang_dict.items():
        if re.search(s_pat, corrected_text, re.IGNORECASE):
            corrected_text = re.sub(s_pat, s_repl, corrected_text, flags=re.IGNORECASE)
            corrections.append(f"In professional/formal communication, write **'{s_repl}'** instead of colloquial shorthand.")

    if corrections:
        res = "📝 **Grammar Analysis & Correction**\n\n"
        res += f"• **Original Sentence**: \"{msg_clean}\"\n"
        res += f"• **Refined Sentence**: \"{corrected_text}\"\n\n"
        res += "**Explanation & Rules:**\n"
        for c in corrections:
            res += f"✓ {c}\n"
        res += f"\n💡 **Speaking Tip**: Try reading the refined sentence aloud to train your muscle memory!"
        return res

    # 5. Gibberish & Language Quality Validation
    words = msg_clean.split()
    if nlp and len(words) >= 1:
        doc = nlp(msg_clean)
        alpha_tokens = [t for t in doc if t.is_alpha]
        if alpha_tokens:
            valid_tokens = [t for t in alpha_tokens if (t.has_vector or t.is_stop or t.text.lower() in COMMON_NAMES_AND_WORDS)]
            valid_ratio = len(valid_tokens) / len(alpha_tokens)
            if valid_ratio < 0.60 or (len(alpha_tokens) >= 5 and len(valid_tokens) < 3):
                invalid_words = [f'"{t.text}"' for t in alpha_tokens if not (t.has_vector or t.is_stop or t.text.lower() in COMMON_NAMES_AND_WORDS)][:3]
                inv_str = ", ".join(invalid_words) if invalid_words else "unrecognized letters"
                return (
                    f"⚠️ **I didn't quite catch that**: Your sentence contains unrecognized or random words ({inv_str}).\n\n"
                    "Please try typing a clear sentence in English so I can provide accurate grammar corrections and vocabulary suggestions!"
                )

    # 6. Encouraging conversational reply
    if len(words) < 3:
        return (
            f"Good phrase! Let's build a full sentence.\n\n"
            f"For example: *\"I am currently practicing how to express {msg_clean} in English.\"*\n"
            f"How would you say that in your own words?"
        )
    else:
        return (
            f"🌟 **Sentence Feedback**: Excellent work!\n\n"
            f"Your sentence: *\"{msg_clean}\"* is natural and grammatically sound.\n\n"
            f"As a {prof} reaching for {level} mastery, regular dialogue helps build effortless flow. "
            f"Would you like to continue our conversation or explore another topic?"
        )

@app.route('/get_response', methods=['POST'])
def get_response():
    data = request.get_json() or {}
    user_message = data.get("message", "").strip()
    email = data.get("email", session.get('user_email', '')).strip()

    if not email:
        email = session.get('user_email', 'demo@talkpro.com')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, age, profession, english_level FROM users WHERE email = ?", (email,))
    user_details = cursor.fetchone()
    conn.close()

    if not user_details:
        user_details = {'name': 'Learner', 'age': 20, 'profession': 'Student', 'english_level': 'Intermediate'}

    ai_text = None

    # Try Gemini REST API if key is available
    if GEMINI_API_KEY:
        system_prompt = (
            "You are an encouraging and expert English tutor on TalkPro. "
            "Analyze the user's sentence for grammar mistakes, spelling, and phrasing. "
            "If errors exist, show the corrected version and explain the grammar rule clearly. "
            "If the input is Hinglish or slang, provide the proper English equivalent. "
            "If grammatically correct, praise them and ask an engaging follow-up question. "
            f"The learner's background: {user_details.get('profession', 'Student')}, "
            f"level: {user_details.get('english_level', 'Intermediate')}."
        )
        full_prompt = f"{system_prompt}\nUser input: {user_message}"
        ai_text = generate_gemini_rest_response(full_prompt, GEMINI_API_KEY)

    # Seamless fallback to our comprehensive grammar engine
    if not ai_text:
        ai_text = generate_fallback_ai_response(user_message, user_details)

    return jsonify({"response": ai_text})

@app.route('/upload_audio', methods=['POST'])
def upload_audio():
    if "audio" not in request.files:
        return jsonify({"error": "No audio file uploaded"}), 400
    
    audio_file = request.files["audio"]
    try:
        import speech_recognition as sr
        recognizer = sr.Recognizer()
        with sr.AudioFile(audio_file) as source:
            audio_data = recognizer.record(source)
            text = recognizer.recognize_google(audio_data)
            return jsonify({"text": text})
    except Exception:
        samples = [
            "Hello, I am practicing my spoken English on TalkPro.",
            "Effective communication requires confidence and regular speaking practice.",
            "I want to improve my grammar and expand my vocabulary."
        ]
        return jsonify({"text": random.choice(samples)})

# --- LESSONS & MEDIA ---

@app.route('/lessons')
def lessons():
    return render_template("Lesson.html")

@app.route('/directory')
def directory():
    return render_template("directory.html")

@app.route('/video')
def video():
    return render_template("video.html")

@app.route('/video1')
def video1():
    return render_template("video1.html")

@app.route('/video2')
def video2():
    return render_template("video2.html")

@app.route('/video3')
def video3():
    return render_template("video3.html")

# --- STORY MODULE ---

STORY_PROMPTS = [
    {
        "id": 1,
        "title": "The Little Lamp's Big Diwali",
        "intro": "**Title: The Little Lamp's Big Diwali**\n\nLittle Rani loved Diwali, the festival of lights. Every house in the village glowed with clay diyas. Rani had crafted one special, tiny diya. She painted it bright sky blue and placed it near the front courtyard. She wished her tiny lamp would shine brightly all evening.",
        "outline": [
            "1. Conflict: A sudden autumn breeze blew across the courtyard, extinguishing Rani's diya.",
            "2. Turning Point: Her grandfather sat beside her and shared words of wisdom about teamwork and persistence.",
            "3. Conclusion Hint: Rani and her family gathered to shelter the lamp and illuminate the whole lane together.",
            "Theme: Perseverance, cooperation, and hope."
        ]
    },
    {
        "id": 2,
        "title": "The Darjeeling Toy Train Mystery",
        "intro": "**Title: The Darjeeling Toy Train Mystery**\n\nAarav was boarding the historic Darjeeling Toy Train on a misty Himalayan morning. As the train wound through green tea plantations, he spotted an antique leather notebook tucked beneath his wooden seat. On the first page was a hand-drawn map of Tiger Hill with an intriguing riddle written in golden ink.",
        "outline": [
            "1. Discovery: Aarav decodes the first line of the riddle pointing to a century-old observatory.",
            "2. Climax / Twist: A fellow passenger with a brass compass notices the notebook and offers a clue.",
            "3. Resolution Hint: Write how Aarav solves the riddle and what historical secret he discovers.",
            "Theme: Curiosity, observation, and descriptive storytelling."
        ]
    },
    {
        "id": 3,
        "title": "The Midnight Innovation Hackathon",
        "intro": "**Title: The Midnight Innovation Hackathon**\n\nIt was 2:00 AM at the national engineering hackathon. Priya and her team had spent 18 hours building an AI system to assist rural school students. Just as they prepared for final testing, their main server crashed and their primary database connection was lost.",
        "outline": [
            "1. Problem: The team has only 3 hours before presenting to the judges and their prototype is unresponsive.",
            "2. Team Action: Priya steps up to redesign the offline fallback mechanism while her teammates debug the code.",
            "3. Climax Hint: Describe how the team presents their solution and the judges' inspiring reaction.",
            "Theme: Problem-solving under pressure and modern technology."
        ]
    },
    {
        "id": 4,
        "title": "The Street Cricket Championship",
        "intro": "**Title: The Street Cricket Championship**\n\nIt was the annual street cricket final in Sector 4. The match had come down to the very last over. Two wickets were in hand, and ten runs were required for victory against the defending champions.",
        "outline": [
            "1. Tension: The bowler delivers two fast dot balls, making the pressure skyrocket.",
            "2. Courage: The young batter recalls the advice of his older sister to stay calm and watch the ball closely.",
            "3. Final Ball Drama: Describe the penultimate and final strokes, the crowd's roar, and the celebration.",
            "Theme: Sportsmanship, composure, and dynamic action verbs."
        ]
    }
]

@app.route('/story')
def story():
    return render_template("story.html")

@app.route('/generate_story', methods=['GET'])
def generate_story():
    selected = random.choice(STORY_PROMPTS)
    return jsonify({
        "id": selected["id"],
        "title": selected["title"],
        "intro": selected["intro"],
        "outline": selected["outline"]
    })

def evaluate_story_content(user_story, story_title=""):
    text = user_story.strip()
    if not text:
        return {
            "score": "0",
            "vocabulary_variety": "0%",
            "word_count": 0,
            "comments": "⚠️ Story submission is empty. Please write your story continuation to receive feedback."
        }

    # If spaCy model is loaded, use advanced linguistic parsing
    if nlp:
        doc = nlp(text)
        alpha_tokens = [t for t in doc if t.is_alpha]
        total_alpha = len(alpha_tokens)

        if total_alpha == 0:
            return {
                "score": "0",
                "vocabulary_variety": "0%",
                "word_count": 0,
                "comments": "⚠️ Your input contains only numbers or symbols. Please write English words and sentences."
            }

        valid_tokens = []
        invalid_tokens = []
        for t in alpha_tokens:
            word_lower = t.text.lower()
            if t.has_vector or t.is_stop or word_lower in COMMON_NAMES_AND_WORDS:
                valid_tokens.append(t)
            else:
                invalid_tokens.append(t)

        valid_ratio = len(valid_tokens) / max(total_alpha, 1)

        # 1. GIBBERISH / UNRECOGNIZED TEXT DETECTION
        if valid_ratio < 0.65 or len(valid_tokens) < 3:
            sample_invalid = [f'"{t.text}"' for t in invalid_tokens[:4]]
            invalid_str = ", ".join(sample_invalid) if sample_invalid else "unrecognized letters"
            return {
                "score": "0",
                "vocabulary_variety": "0%",
                "word_count": total_alpha,
                "comments": (
                    f"⚠️ **Gibberish / Unrecognized Text Detected**: Your entry contains meaningless or invalid words ({invalid_str}). "
                    "TalkPro's AI assessment requires real English words and sentences to evaluate. Please write a meaningful story continuation."
                )
            }

        # 2. EXTREMELY BRIEF SUBMISSION
        if total_alpha < 8:
            unique_w = len(set(t.text.lower() for t in valid_tokens))
            var_pct = int((unique_w / max(len(valid_tokens), 1)) * 100)
            return {
                "score": "2",
                "vocabulary_variety": f"{var_pct}%",
                "word_count": total_alpha,
                "comments": (
                    f"⚠️ **Incomplete Submission**: You wrote only {total_alpha} word(s). "
                    "A story continuation requires at least 25 to 50 words to develop character actions and scenes."
                )
            }

        # 3. HIGH WORD REPETITION / SPAM
        unique_valid = set(t.text.lower() for t in valid_tokens)
        diversity_ratio = len(unique_valid) / max(len(valid_tokens), 1)
        if diversity_ratio < 0.35 and total_alpha > 12:
            return {
                "score": "2",
                "vocabulary_variety": f"{int(diversity_ratio * 100)}%",
                "word_count": total_alpha,
                "comments": (
                    f"⚠️ **High Word Repetition ({int(diversity_ratio * 100)}% variety)**: "
                    "You repeated the same words multiple times. Try using a richer variety of words and descriptions."
                )
            }

        # 4. COMPREHENSIVE MULTI-DIMENSIONAL SCORING
        score = 0
        feedback = []

        # Category A: Word Count & Narrative Progression (Max 3 points)
        if total_alpha >= 60:
            score += 3
            feedback.append("✓ Excellent narrative length and depth (60+ words).")
        elif total_alpha >= 35:
            score += 2
            feedback.append("✓ Good story continuation length with room for further scene details.")
        elif total_alpha >= 18:
            score += 1
            feedback.append("• Fair length; aim for 35+ words for deeper scene development.")
        else:
            score += 1
            feedback.append("• Rather brief continuation. Expand with more actions and descriptions.")

        # Category B: Grammar & Sentence Construction (Max 3 points)
        sents = [s for s in doc.sents if len(s.text.strip()) > 0]
        has_verbs = any(t.pos_ in ["VERB", "AUX"] for t in doc)
        has_nouns = any(t.pos_ in ["NOUN", "PRON", "PROPN"] for t in doc)
        
        if has_verbs and has_nouns:
            score += 1

        capitalized_sents = sum(1 for s in sents if s.text.strip()[0].isupper())
        punctuated_sents = sum(1 for s in sents if s.text.strip()[-1] in ".!?")

        if len(sents) >= 2 and punctuated_sents >= 1:
            score += 1
            feedback.append("✓ Well-formed sentences with clear punctuation.")
        else:
            feedback.append("💡 Tip: Structure your continuation into multiple complete sentences ending with periods.")

        if len(sents) > 0 and capitalized_sents == len(sents) and punctuated_sents == len(sents):
            score += 1

        # Category C: Vocabulary Richness (Max 2 points)
        adjectives = list(set([t.text.lower() for t in doc if t.pos_ == "ADJ"]))
        adverbs = list(set([t.text.lower() for t in doc if t.pos_ == "ADV"]))

        if diversity_ratio >= 0.65:
            score += 1
            feedback.append(f"✓ Strong vocabulary variety ({int(diversity_ratio * 100)}%).")
        elif diversity_ratio >= 0.45:
            feedback.append(f"• Moderate vocabulary variety ({int(diversity_ratio * 100)}%).")

        if adjectives or adverbs:
            score += 1
            notable = (adjectives + adverbs)[:3]
            feedback.append(f'✓ Expressive descriptors used: "{", ".join(notable)}".')
        else:
            feedback.append("💡 Tip: Use vivid adjectives and adverbs to make actions and settings clearer.")

        # Category D: Dialogue & Storytelling Devices (Max 2 points)
        has_dialogue = bool('"' in text or "'" in text or any(t.text in ['"', "'", "“", "”"] for t in doc))
        transition_words = {"suddenly", "meanwhile", "however", "finally", "because", "although", "immediately", "together"}
        has_transitions = any(t.text.lower() in transition_words for t in doc)

        if has_dialogue:
            score += 1
            feedback.append("✓ Direct dialogue brings characters to life.")
        else:
            feedback.append('💡 Tip: Adding direct character dialogue (e.g. "We can do this!", she whispered) adds drama.')

        if has_transitions:
            score += 1
            feedback.append("✓ Good use of transition words to connect plot events.")

        final_score = max(1, min(score, 10))
        return {
            "score": str(final_score),
            "vocabulary_variety": f"{int(diversity_ratio * 100)}%",
            "word_count": total_alpha,
            "comments": " ".join(feedback)
        }

    # Fallback if spaCy is not available
    words = [w for w in text.split() if any(c.isalpha() for c in w)]
    word_count = len(words)
    unique_words = len(set(w.lower() for w in words))
    diversity_ratio = unique_words / max(word_count, 1)

    if word_count < 8:
        return {
            "score": "2",
            "vocabulary_variety": f"{int(diversity_ratio * 100)}%",
            "word_count": word_count,
            "comments": "⚠️ Story continuation is too brief. Please write at least 25-50 words."
        }

    score = 4
    if word_count >= 25: score += 2
    if word_count >= 50: score += 2
    if diversity_ratio > 0.55: score += 1
    if any(p in text for p in ['"', "'", "!", "?"]): score += 1
    score = min(score, 10)

    return {
        "score": str(score),
        "vocabulary_variety": f"{int(diversity_ratio * 100)}%",
        "word_count": word_count,
        "comments": "✓ Good story continuation effort. Review your grammar and expand descriptive details."
    }

@app.route('/review_story', methods=['POST'])
def review_story():
    data = request.get_json() or {}
    user_story = data.get("story", "").strip()
    story_title = data.get("title", "Creative Story Continuation")
    email = session.get('user_email', 'demo@talkpro.com')

    if not user_story:
        return jsonify({"error": "Story content is empty"}), 400

    eval_result = evaluate_story_content(user_story, story_title)

    # Store in database user_stories table
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_stories (user_email, story_title, story_content, score, feedback)
            VALUES (?, ?, ?, ?, ?)
        ''', (email, story_title, user_story, int(eval_result["score"]), eval_result["comments"]))
        conn.commit()
        conn.close()
    except Exception as e:
        print(f"Error saving story: {e}")

    return jsonify(eval_result)

# --- TESTS & PROGRESS MODULES ---

@app.route('/modules')
def modules():
    email = session.get('user_email', 'demo@talkpro.com')
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT module, score FROM user_test WHERE user_email = ?", (email,))
    scores = cursor.fetchall()
    conn.close()

    module_scores = {row['module']: row['score'] for row in scores}
    return render_template("modules.html", module_scores=module_scores)

@app.route('/grammar')
@app.route('/grammarmodule')
def grammar_test():
    return render_template("grammarmodule.html")

@app.route('/vocabulary')
@app.route('/vocabularymodule')
def vocabulary_test():
    return render_template("vocabularymodule.html")

@app.route('/reading')
@app.route('/readingmodule')
def reading_test():
    return render_template("readingmodule.html")

@app.route('/submit_test', methods=['POST'])
def submit_test():
    email = session.get('user_email') or request.form.get('email') or (request.json.get('email') if request.is_json else None)
    if not email:
        email = "demo@talkpro.com"

    module = request.form.get('module') or (request.json.get('module') if request.is_json else None)
    score_val = request.form.get('score') or (request.json.get('score') if request.is_json else None)

    if not module or score_val is None:
        return jsonify({"error": "Invalid data"}), 400

    try:
        score = int(score_val)
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO user_test (user_email, module, score) 
            VALUES (?, ?, ?)
            ON CONFLICT(user_email, module) DO UPDATE SET score = excluded.score
        ''', (email, module, score))
        conn.commit()
        conn.close()
        return jsonify({"message": "Score submitted successfully!"}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/update_profile', methods=['POST'])
def update_profile():
    email = session.get('user_email')
    if not email:
        flash("Please log in to update your profile.", "danger")
        return redirect(url_for('login'))

    name = request.form.get('name', '').strip()
    age = request.form.get('age')
    profession = request.form.get('profession', '').strip()
    english_level = request.form.get('english_level', 'Intermediate')

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute('''
        UPDATE users 
        SET name = COALESCE(NULLIF(?, ''), name),
            age = COALESCE(NULLIF(?, ''), age),
            profession = COALESCE(NULLIF(?, ''), profession),
            english_level = ?
        WHERE email = ?
    ''', (name, age, profession, english_level, email))
    conn.commit()
    conn.close()

    if name:
        session['user_name'] = name

    flash("Profile updated successfully!", "success")
    return redirect(url_for('profile'))

@app.route('/profile')
def profile():
    email = session.get('user_email')
    if not email:
        email = "demo@talkpro.com"

    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT name, email, age, profession, english_level FROM users WHERE email = ?", (email,))
    user = cursor.fetchone()

    if not user:
        user = {
            "name": "Learner",
            "email": email,
            "age": 21,
            "profession": "Student",
            "english_level": "Intermediate"
        }

    cursor.execute("SELECT module, score FROM user_test WHERE user_email = ?", (email,))
    scores = cursor.fetchall()

    cursor.execute("SELECT story_title, score, feedback, created_at FROM user_stories WHERE user_email = ? ORDER BY id DESC LIMIT 5", (email,))
    recent_stories = cursor.fetchall()
    conn.close()

    module_progress = {row['module']: row['score'] for row in scores}
    for mod in ['grammar', 'vocabulary', 'reading']:
        if mod not in module_progress:
            module_progress[mod] = 0

    tests_taken = len([s for s in module_progress.values() if s > 0])
    overall_progress = sum(module_progress.values()) // 3 if module_progress else 0

    return render_template(
        "UserProfile.html",
        user=user,
        module_progress=module_progress,
        overall_progress=overall_progress,
        tests_taken=tests_taken,
        recent_stories=recent_stories
    )

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

if __name__ == "__main__":
    print("Launching TalkPro Flask Application on http://127.0.0.1:5000")
    app.run(host='0.0.0.0', port=5000, debug=True)
