"""
TalkPro Database Inspector
Run this script anytime to inspect registered users, test scores, and story submissions.
Usage:
    py view_users.py
"""

from database import get_db

def view_all():
    conn = get_db()
    cursor = conn.cursor()

    print("=" * 80)
    print(" TALKPRO USER ACCOUNTS (elib.db)")
    print("=" * 80)

    cursor.execute("SELECT id, name, email, age, profession, english_level FROM users ORDER BY id ASC")
    users = cursor.fetchall()

    if not users:
        print("No users found in the database.")
    else:
        print(f"{'ID':<4} | {'Name':<18} | {'Email':<26} | {'Age':<4} | {'Profession':<16} | {'Level'}")
        print("-" * 80)
        for u in users:
            name = (u['name'] or 'N/A')[:18]
            email = (u['email'] or 'N/A')[:26]
            age = str(u['age'] or '-')
            prof = (u['profession'] or 'N/A')[:16]
            lvl = u['english_level'] or 'N/A'
            print(f"{u['id']:<4} | {name:<18} | {email:<26} | {age:<4} | {prof:<16} | {lvl}")

    print("\n" + "=" * 80)
    print(" RECENT USER STORY SUBMISSIONS")
    print("=" * 80)
    cursor.execute("SELECT id, user_email, story_title, score, created_at FROM user_stories ORDER BY id DESC LIMIT 5")
    stories = cursor.fetchall()

    if not stories:
        print("No story submissions found.")
    else:
        print(f"{'ID':<4} | {'User Email':<26} | {'Score':<6} | {'Title':<25} | {'Date'}")
        print("-" * 80)
        for s in stories:
            email = (s['user_email'] or '')[:26]
            score = f"{s['score']}/10"
            title = (s['story_title'] or '')[:25]
            date = str(s['created_at'] or '')[:19]
            print(f"{s['id']:<4} | {email:<26} | {score:<6} | {title:<25} | {date}")

    print("\n" + "=" * 80)
    print(" RECENT MODULE TEST SCORES")
    print("=" * 80)
    cursor.execute("SELECT user_email, module, score FROM user_test ORDER BY id DESC LIMIT 10")
    tests = cursor.fetchall()

    if not tests:
        print("No test scores recorded yet.")
    else:
        print(f"{'User Email':<30} | {'Module':<15} | {'Score'}")
        print("-" * 80)
        for t in tests:
            email = (t['user_email'] or '')[:30]
            module = (t['module'] or '')[:15]
            print(f"{email:<30} | {module:<15} | {t['score']}%")

    print("=" * 80 + "\n")
    conn.close()

if __name__ == "__main__":
    view_all()
