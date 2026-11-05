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

הסוד הוא חובה: כל עוד `WEBHOOK_SECRET` ריק, ה-workflow דוחה כל התראה (תשובת HTTP 503). כך אי אפשר לשכוח אותו ולהשאיר את ה-webhook פתוח לכל מי שברשת.

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

**פרטיות:** המודל רץ אצלך, אבל הודעת הטלגרם יוצאת לשרתים של טלגרם, והיא כוללת שם מחשב, שם משתמש, כתובת IP, את הכלל ואת סיכום ה-AI. אם זה לא מתאים לך:
- `TELEGRAM_ENABLED=false` מכבה את טלגרם לגמרי. התוצאות נשארות במסך Executions של n8n.
- `NOTIFY_REDACT=true` מסתיר בהודעה את שם המחשב ואת שמות המשתמשים.

### 3. להפעיל את n8n מחדש עם ההגדרות
ה-n8n שהפעלת קודם לא מכיר את ההגדרות האלה, אז מחליפים אותו. החשבון שלך נשמר.
```powershell
docker rm -f n8n
docker compose up -d
```

### 4. לייבא את ה-workflow
אם ייבאת גרסה קודמת של ה-workflow, מחק אותה קודם (או בטל את הפרסום שלה), כדי שלא יהיו שני workflows על אותה כתובת.
1. פתח את `http://localhost:5678`.
2. צור workflow חדש. בתפריט **⋯** למעלה בחר **Import from File**, ובחר את `C:\wazuh-ai-triage\workflows\wazuh-ai-triage.json`.
3. לחץ **Publish** (למעלה מימין). רק workflow שפורסם מקבל התראות אמיתיות.

### 5. בדיקה ראשונה, עדיין בלי Wazuh
ודא ש-LM Studio פתוח והשרת שלו ב-Running. אז הרץ:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1
```
הסקריפט אמור לכתוב `HTTP 202`. המשמעות: n8n קיבל את ההתראה לניתוח. זה עוד לא אומר שההודעה נשלחה, כי הניתוח קורה אחרי התשובה. תוך כמה שניות אמורה להגיע לטלגרם הודעה על "SSH brute force". ב-n8n, במסך **Executions**, אפשר לראות כל שלב ומה יצא ממנו.

בדוגמאות יש כתובות IP מטווחי תיעוד (כמו `203.0.113.45`), שאינן כתובות אמיתיות באינטרנט. לכן ההודעה תכתוב `source IP is not public`, לא תהיה בדיקת AbuseIPDB ולא תהיה המלצה לחסום. זה תקין.

אפשר לשלוח גם את שאר הדוגמאות, למשל:
```powershell
powershell -ExecutionPolicy Bypass -File scripts\send-alert.ps1 -File samples\alerts\02-web-sql-injection.json
```
הסקריפט נותן לכל שליחה מזהה התראה חדש. אותה דוגמה שנשלחת שוב בתוך 10 דקות תקובץ עם הראשונה ולא תיצור הודעה נוספת, וזה בכוונה (סינון כפילויות).

### 6. לפתוח את הדלת לנייד, ורק לו
הנייד צריך להגיע ל-n8n דרך הרשת הביתית. כדי שרק הוא יוכל, החוק מתיר חיבור רק מהכתובת של הנייד.
1. בנייד, הרץ `hostname -I` ורשום את הכתובת הראשונה (למשל `192.168.1.30`).
2. בנייח, ב-PowerShell **כמנהל** (קליק ימני ואז Run as administrator), עם הכתובת של הנייד:
```powershell
New-NetFirewallRule -DisplayName "n8n webhook 5678 (Wazuh only)" -Direction Inbound -Protocol TCP -LocalPort 5678 -RemoteAddress 192.168.1.30 -Action Allow -Profile Private
```
3. הרץ `ipconfig` ורשום את ה-**IPv4 Address** של הנייח (למשל `192.168.1.20`).

כדאי שהנייד יקבל כתובת קבועה בראוטר (DHCP reservation), אחרת החוק יפסיק לעבוד כשהכתובת תשתנה.

התעבורה בין הנייד לנייח היא HTTP רגיל, לא מוצפן. ברשת ביתית זה סביר למעבדה. אם המחשבים לא באותה רשת, אל תפתח את הפורט לאינטרנט: השתמש ב-VPN כמו Tailscale או WireGuard.

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

הסקריפט שומר גיבוי של ההגדרות של Wazuh ושל קובצי החיבור הקודמים. אם משהו נכשל באמצע, או ש-Wazuh לא עולה אחרי השינוי, הסקריפט מחזיר את כל הגיבוי לבד.

אם תריץ את הסקריפט שוב בלי `WEBHOOK_SECRET`, הוא שומר את הסוד הקיים, כדי שהחיבור ל-n8n לא יישבר. כדי ליצור סוד חדש בכוונה, הרץ עם `ROTATE_SECRET=1`, והעתק את הסוד החדש גם ל-`.env` בנייח.

---

## חלק ד: בדיקה אמיתית מקצה לקצה

ניצור התקפת ניחוש סיסמאות קטנה על הנייד עצמו. אם אין SSH בנייד, התקן קודם: `sudo apt install -y openssh-server`.
```bash
for i in $(seq 1 10); do ssh -o BatchMode=yes -o StrictHostKeyChecking=no fakeuser@127.0.0.1 true; done
```
Wazuh יזהה את זה כ-brute force (רמה 10), ותוך כמה שניות תגיע הודעה לטלגרם. מכיוון שהכתובת היא `127.0.0.1` (פנימית), לא תהיה בדיקת AbuseIPDB ולא תהיה המלצה לחסום. זה תקין.

---

## חלק ה: מה קורה כשמשהו נכשל

- **n8n כבוי או לא זמין:** הסקריפט בנייד מנסה 3 פעמים. אם זה לא עובד, ההתראה נשמרת בתיקייה `/var/ossec/logs/custom-n8n-spool/`, ונשלחת שוב אוטומטית בהתראה הבאה. אפשר גם לשלוח הכל ידנית:
  ```bash
  sudo /var/ossec/integrations/custom-n8n --flush
  ```
  התראה שנכשלת יותר מ-50 פעמים או יותר מ-3 ימים עוברת ל-`custom-n8n-spool/failed/`, ונכתבת שורת `ERROR` ב-`integrations.log`. כך שום התראה לא נעלמת בשקט.
- **טלגרם נכשל:** n8n מנסה 3 פעמים. אם עדיין נכשל, ההרצה מסומנת ב-Executions כנכשלת (אדום). פתח אותה, תקן את הבעיה, ולחץ **Retry**.
- **המודל ענה תשובה לא תקינה:** ההודעה תגיד `AI: analysis failed` ותציג את החומרה של Wazuh. במקרה כזה אף פעם אין המלצת חסימה.

---

## תקלות נפוצות

| מה רואים | מה לבדוק |
| --- | --- |
| לא מגיעה הודעה לטלגרם | ב-n8n, במסך Executions, פתח את ההרצה האחרונה. אם היא אדומה בשלב Result, השגיאה מסבירה למה טלגרם לא קיבל את ההודעה. |
| הסקריפט מקבל HTTP 401 | הסוד ב-`.env` בנייח לא זהה לסוד שבנייד (`<api_key>` ב-`ossec.conf`). |
| הסקריפט מקבל HTTP 503 | `WEBHOOK_SECRET` ריק ב-`.env`. מלא אותו והרץ `docker compose up -d`. |
| הסקריפט מקבל HTTP 400 | הקובץ שנשלח הוא לא התראת Wazuh תקינה. |
| שלב LLM Triage נכשל עם connection refused | ש-LM Studio פתוח, שהשרת ב-Running ושהמודל טעון. אם עדיין לא עובד, הפעל בהגדרות השרת של LM Studio את **Serve on Local Network**. |
| הניתוח לוקח הרבה זמן | Qwen3.5 "חושב" לפני שהוא עונה. זה תקין, אבל אם זה מפריע, נסה מודל קטן יותר או כבה את ה-thinking בהגדרות המודל ב-LM Studio. |
| ההרצה נעצרת בשלב Accepted? | הבקשה נדחתה (401/400/503, ראו למעלה). |
| ההרצה נעצרת בשלב Deduplicate | זו כפילות שסוננה, וזה בכוונה. |
| ההודעה אומרת `Config: ...` | ערך לא תקין ב-`.env` (למשל `BLOCK_THRESHOLD`). ההודעה מסבירה מה לתקן. |
| הנייד לא מגיע לנייח | חוק ה-firewall, וש-Windows מגדיר את הרשת הביתית כ-Private. |
| בבדיקה של חלק ד לא מופיעה התראה גם ב-Wazuh Dashboard | ייתכן ש-Wazuh לא קורא את `/var/log/auth.log`. בדוק ש-`rsyslog` מותקן ושהקובץ מתעדכן. |
| מה קרה בצד של Wazuh? | `sudo tail -f /var/ossec/logs/integrations.log` |
| יש התראות שמחכות בצד של Wazuh? | `sudo ls /var/ossec/logs/custom-n8n-spool/` |
