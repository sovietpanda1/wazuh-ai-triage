# מדריך התקנה צעד אחר צעד

המדריך מניח את המעבדה הזו:
- **המחשב הנייח (Windows):** מריץ את n8n ב-Docker ואת LM Studio עם המודל.
- **הנייד (Ubuntu):** מריץ את שרת Wazuh.

מה שכבר עובד אצלך: השרת של LM Studio ענה דרך ה-API, ו-Docker Desktop ו-n8n רצים.

---

## חלק א: הכנות (בערך 10 דקות)

### 1. בוט טלגרם
1. בטלגרם, חפש את **@BotFather** ושלח לו `/newbot`.
2. תן לבוט שם, ואחר כך שם משתמש שנגמר ב-`bot` (למשל `my_soc_bot`).
3. BotFather ישלח לך **טוקן** שנראה בערך כך: `123456789:AA...`. שמור אותו ואל תשתף אותו עם אף אחד.
4. פתח את הצ'אט עם הבוט החדש ושלח לו `/start`.
5. בדפדפן, פתח את הכתובת הזו אחרי שהחלפת `<TOKEN>` בטוקן שלך:
   `https://api.telegram.org/bot<TOKEN>/getUpdates`
6. חפש בטקסט שמופיע `"chat":{"id":` עם מספר אחריו. המספר הזה הוא ה-**Chat ID**.

### 2. מפתח AbuseIPDB (רשות, אבל מומלץ)
1. הירשם בחינם ב-[abuseipdb.com](https://www.abuseipdb.com).
2. היכנס ל-Account, משם ל-API, ולחץ **Create Key**.

### 3. סוד משותף בין Wazuh ל-n8n
ב-PowerShell בנייח, הרץ:
```powershell
-join ((1..32) | ForEach-Object { '{0:x}' -f (Get-Random -Maximum 16) })
```
יוצא רצף של 32 תווים. שמור אותו, כי תצטרך אותו גם בנייח וגם בנייד.

---

## חלק ב: המחשב הנייח (Windows)

### 1. להוריד את הקוד
ב-GitHub, בדף של הפרויקט, לחץ **Code** ואחר כך **Download ZIP**. חלץ את הקבצים ל-`C:\wazuh-ai-triage`.

### 2. למלא את ההגדרות
ב-PowerShell:
```powershell
cd C:\wazuh-ai-triage
copy .env.example .env
notepad .env
```
ב-Notepad, מלא את השורות האלה ושמור:
```
WEBHOOK_SECRET=<הסוד מחלק א>
LLM_MODEL=qwen/qwen3.5-9b
ABUSEIPDB_API_KEY=<המפתח מ-AbuseIPDB>
TELEGRAM_BOT_TOKEN=<הטוקן מ-BotFather>
TELEGRAM_CHAT_ID=<ה-Chat ID>
```
הקובץ `.env` נשאר רק אצלך במחשב, ולעולם לא עולה ל-GitHub.

### 3. להפעיל את n8n מחדש עם ההגדרות
ה-n8n שהפעלת קודם לא מכיר את ההגדרות האלה, אז מחליפים אותו. החשבון שלך נשמר.
```powershell
docker rm -f n8n
docker compose up -d
```

### 4. לייבא את ה-workflow
1. פתח את `http://localhost:5678`.
2. צור workflow חדש. בתפריט **⋯** למעלה בחר **Import from File**, ובחר את `C:\wazuh-ai-triage\workflows\wazuh-ai-triage.json`.
3. לחץ **Publish** (למעלה מימין). רק workflow שפורסם מקבל התראות אמיתיות.

### 5. בדיקה ראשונה, עדיין בלי Wazuh
ודא ש-LM Studio פתוח והשרת שלו ב-Running. אז הרץ:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1
```
תוך כמה שניות אמורה להגיע לטלגרם הודעה על "SSH brute force". ב-n8n, במסך **Executions**, אפשר לראות כל שלב ומה יצא ממנו.

אפשר לשלוח גם את שאר הדוגמאות, למשל:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -File samples\alerts\02-web-sql-injection.json
```
אותה התראה שנשלחת שוב בתוך 10 דקות תסונן, וזה בכוונה (סינון כפילויות).

### 6. לפתוח את הדלת לנייד
הנייד צריך להגיע ל-n8n דרך הרשת הביתית. ב-PowerShell **כמנהל** (קליק ימני ואז Run as administrator):
```powershell
New-NetFirewallRule -DisplayName "n8n webhook 5678" -Direction Inbound -Protocol TCP -LocalPort 5678 -Action Allow -Profile Private
```
אחר כך הרץ `ipconfig` ורשום את ה-**IPv4 Address** של הנייח (למשל `192.168.1.20`).

---

## חלק ג: הנייד (Ubuntu, שרת Wazuh)

### 1. להוריד את הקוד
```bash
sudo apt install -y git
git clone https://github.com/sovietpanda1/wazuh-ai-triage.git
cd wazuh-ai-triage
```

### 2. לבדוק שהנייד מגיע ל-n8n
```bash
curl http://192.168.1.20:5678/healthz
```
החלף את ה-IP בכתובת של הנייח. אמור לחזור `{"status":"ok"}`. אם לא חוזר כלום, בדוק את חוק ה-firewall מחלק ב.

### 3. להתקין את החיבור
```bash
sudo WEBHOOK_SECRET=<הסוד מחלק א> ./wazuh/install-integration.sh http://192.168.1.20:5678/webhook/wazuh-alert 7
```
המספר 7 בסוף הוא רמת החומרה המינימלית: רק התראות ברמה 7 ומעלה יישלחו לניתוח.

הסקריפט שומר גיבוי של ההגדרות של Wazuh. אם Wazuh לא עולה אחרי השינוי, הסקריפט מחזיר את הגיבוי לבד.

---

## חלק ד: בדיקה אמיתית מקצה לקצה

ניצור התקפת ניחוש סיסמאות קטנה על הנייד עצמו. אם אין SSH בנייד, התקן קודם: `sudo apt install -y openssh-server`.
```bash
for i in $(seq 1 10); do ssh -o BatchMode=yes -o StrictHostKeyChecking=no fakeuser@127.0.0.1 true; done
```
Wazuh יזהה את זה כ-brute force (רמה 10), ותוך כמה שניות תגיע הודעה לטלגרם. מכיוון שהכתובת היא `127.0.0.1` (פנימית), לא תהיה בדיקת AbuseIPDB ולא תהיה המלצה לחסום. זה תקין.

---

## תקלות נפוצות

| מה רואים | מה לבדוק |
| --- | --- |
| לא מגיעה הודעה לטלגרם | ב-n8n, במסך Executions, פתח את ההרצה האחרונה ובדוק את השלב Result. השדה notification מסביר למה. |
| שלב LLM Triage נכשל עם connection refused | ש-LM Studio פתוח, שהשרת ב-Running ושהמודל טעון. אם עדיין לא עובד, הפעל בהגדרות השרת של LM Studio את **Serve on Local Network**. |
| הניתוח לוקח הרבה זמן | Qwen3.5 "חושב" לפני שהוא עונה. זה תקין, אבל אם זה מפריע, נסה מודל קטן יותר או כבה את ה-thinking בהגדרות המודל ב-LM Studio. |
| ההרצה נעצרת בשלב Sanitize & Validate | הסוד ב-`.env` לא זהה לסוד שבנייד, או שהבקשה היא לא התראת Wazuh. |
| ההרצה נעצרת בשלב Deduplicate | זו כפילות שסוננה, וזה בכוונה. |
| הנייד לא מגיע לנייח | חוק ה-firewall, וש-Windows מגדיר את הרשת הביתית כ-Private. |
| בבדיקה של חלק ד לא מופיעה התראה גם ב-Wazuh Dashboard | ייתכן ש-Wazuh לא קורא את `/var/log/auth.log`. בדוק ש-`rsyslog` מותקן ושהקובץ מתעדכן. |
| מה קרה בצד של Wazuh? | `sudo tail -f /var/ossec/logs/integrations.log` |
