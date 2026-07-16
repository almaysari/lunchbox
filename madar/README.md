# People Desk — منصة سحب السير الذاتية من بريد HR

منصة خفيفة تسحب رسائل البريد التي تحتوي سيرًا ذاتية (PDF / DOC / DOCX) من Zoho Mail
عبر OAuth 2.0، وتعرضها في لوحة عربية مع معاينة المرفقات وإدارة حالة كل متقدم.

بدون أي مكتبات خارجية — تحتاج Node.js 18 أو أحدث فقط.

## التشغيل السريع (وضع تجريبي)

```bash
cd people-desk
cp .env.example .env
node server.js
```

ثم افتح <http://localhost:3000> — ستجد سيرًا ذاتية وهمية للتجربة.

## الربط الحقيقي مع Zoho Mail

### 1. أنشئ تطبيق OAuth

1. ادخل إلى <https://api-console.zoho.com>.
2. اختر **Server-based Applications**.
3. ضع Redirect URI: `http://localhost:3000/oauth/callback`.
4. انسخ `Client ID` و `Client Secret` إلى ملف `.env` وغيّر `MODE=live`.

> إذا كان حسابك على مركز بيانات غير `.com` (مثل `.sa` أو `.eu`)، عدّل
> `ZOHO_ACCOUNTS_BASE` و `ZOHO_MAIL_BASE` معًا في `.env`.

### 2. اربط الحساب

شغّل `node server.js` وافتح المنصة، ثم اضغط رابط **ربط حساب Zoho** في الشريط الأصفر.
سيوجهك إلى صفحة موافقة Zoho بالصلاحيات التالية (قراءة فقط):

```
ZohoMail.accounts.READ
ZohoMail.folders.READ
ZohoMail.messages.READ
```

بعد الموافقة يُحفظ `refresh_token` في `data/tokens.json` (خارج git) وتبدأ المزامنة.

### 3. صندوق HR المشترك (Shared Mailbox) — مهم

Zoho **لا يسمح** بقراءة رسائل الـShared Mailbox مباشرة عبر Mail API
(يرجع `Invalid Account ID`)، لأن الصندوق المشترك ليس حساب مستخدم له `accountId`.

الحل الموصى به للربط الكامل والمستقر:

1. أنشئ حساب مستخدم مستقل مثل `hr.integration@yourcompany.com`
   (من Admin Console، يحتاج ترخيص مستخدم).
2. من إعدادات صندوق HR المشترك، فعّل **تحويل تلقائي (Forward)** لكل الرسائل
   الواردة إلى حساب التكامل.
3. ضع `ZOHO_MAILBOX=hr.integration@yourcompany.com` في `.env`.
4. اربط المنصة بحساب التكامل (الخطوة 2 أعلاه) — بهذا تصل كل رسائل HR الجديدة
   تلقائيًا وتسحبها المنصة.
5. للأرشيف القديم: استخدم تصدير البريد من Admin Console ثم أعد إرساله أو
   استورده لحساب التكامل.

لماذا حساب تكامل وليس حساب موظف؟ لأن الربط لا يتعطل عند مغادرة الموظف أو
تغيير صلاحياته، وصلاحيات النظام تبقى محصورة في صندوق واحد مخصص.

## أداة الفحص: هل يمكن قراءة الصندوق المشترك مباشرة؟

قبل أي قرار معماري (حساب تكامل / تحويل)، شغّل أداة التشخيص للحصول على دليل فعلي
من واجهات Zoho الرسمية نفسها:

```bash
node scripts/diagnose.js
```

تحتاج أولًا إنشاء **Self Client** من <https://api-console.zoho.com> وتوليد Code
(صلاحية 10 دقائق) بهذه الصلاحيات — قراءة فقط:

```
ZohoMail.accounts.READ,ZohoMail.folders.READ,ZohoMail.messages.READ,ZohoMail.organization.accounts.READ,ZohoMail.organization.groups.READ
```

الأداة تنفّذ طلبات GET فقط وتختبر بالترتيب:

1. `GET /api/accounts` — هل يظهر الصندوق المستهدف بـ`accountId` خاص به؟
2. `GET /api/organization` ثم `GET /api/organization/{zoid}/groups` — هل هو مسجّل
   كمجموعة؟ وما نوعه بالضبط (البيانات الخام كاملة)؟
3. `GET .../groups/{groupId}/messages` — ماذا يرجع مسار رسائل المجموعة الرسمي فعليًا؟
4. استخدام `groupId` مكان `accountId` — لتوثيق نص الخطأ الحقيقي (`Invalid Account ID` أو غيره).
5. `GET /api/organization/{zoid}/accounts` — هل يظهر الصندوق بحساب على مستوى المؤسسة
   يمكن القراءة منه؟
6. قراءة مجلدات وأول رسائل كل صندوق ظاهر — لإثبات ما هو متاح فعلًا.

النتيجة تُكتب في `data/diagnose-report.json` (بدون أي توكنات — تُحذف قبل الكتابة)
ويمكن مشاركتها للتحليل بأمان.

## كيف تعمل المزامنة

```
رسالة جديدة في الصندوق
        ↓
GET /api/accounts ← تحديد accountId
        ↓
مسح مجلد Inbox (أو ZOHO_FOLDER)
        ↓
تجاهل الرسائل المستوردة سابقًا (messageId محفوظ في data/db.json)
        ↓
فحص المرفقات: pdf / doc / docx فقط، بحد أقصى 15MB
        ↓
تنزيل المرفق إلى data/cvs/ وإنشاء سجل متقدم
```

- منع التكرار يعتمد على `messageId` وليس حالة "مقروء/غير مقروء"
  (لأن الصندوق مشترك مع فريق HR).
- المزامنة تلقائية كل `SYNC_INTERVAL_MINUTES` دقيقة، أو يدويًا بزر "مزامنة الآن".

## الأمان والخصوصية

- لا تُستخدم كلمة مرور البريد إطلاقًا — OAuth فقط، بصلاحيات قراءة فقط.
- `data/` بالكامل خارج git (يحتوي tokens وسيرًا ذاتية — بيانات شخصية للمتقدمين).
- يُنصح بفحص الملفات ضد البرمجيات الضارة قبل مشاركتها، وتحديد مدة احتفاظ
  بملفات المتقدمين بما يوافق سياسة الخصوصية لديكم.

## واجهة الـAPI

| المسار | الوصف |
|---|---|
| `GET /api/status` | حالة الاتصال والمزامنة |
| `GET /api/candidates?q=` | قائمة المتقدمين مع بحث |
| `POST /api/candidates/:id/status` | تغيير حالة متقدم (new/reviewed/shortlisted/rejected) |
| `GET /cv/:file` | معاينة/تنزيل السيرة الذاتية |
| `POST /api/sync` | تشغيل مزامنة فورية |
| `GET /api/oauth/url` | رابط موافقة Zoho |
| `GET /oauth/callback` | استقبال كود OAuth وحفظ refresh token |
