# مدار (Madar) — منصة الشركة الموحدة

منصة داخلية للشركة؛ **قسم البريد** هو الوحدة الأولى: مركز موحد لجميع صناديق بريد
الشركة على Zoho (والمزوّدون الآخرون مستقبلًا عبر نفس طبقة الـConnectors).

> **بيئة الشركة الحالية:** 20 Zoho Shared Mailboxes عبر النطاقين
> `exoticcolors.org` و`thetaurus.world` — الصندوق المشترك هو الحالة الأساسية
> في التصميم، وليس حالة جانبية. راجع `docs/COMPANY-ENVIRONMENT.md`.
>
> **مصطلحات صارمة:** نتائج الوضع التجريبي تُسمى Mock Discovery، والمقارنة
> بالقائمة المرجعية Fixture Validation؛ عبارة «Zoho أعاد X» محجوزة حصريًا
> لنتائج Live Zoho API Discovery بعد OAuth حقيقي.
> ما ثبت وما لم يثبت بعد: `docs/VERIFICATION-STATUS.md`.

قاعدة التشغيل: **PostgreSQL** في كل الأوضاع (تطوير، live، إنتاج، اختبارات
تكاملية). Node.js ≥ 20، والتبعية الوحيدة هي سائق `pg`.
راجع `docs/DECISIONS.md` لسبب إزالة SQLite نهائيًا من مسار التشغيل.

## التشغيل (الإنتاج/التطوير)

```bash
cd madar
cp .env.example .env    # عبّئ POSTGRES_PASSWORD والسرّين (openssl rand -hex 32)
docker compose up -d postgres
npm install
npm run migrate
npm run create-admin    # يطلب البريد وكلمة المرور بأمان — لا admin افتراضي
npm start               # افتح http://localhost:3000
```

أو بالكامل عبر Docker: `docker compose up -d` (مع volumes دائمة للقاعدة
والمرفقات وHealth checks — انظر `docker-compose.yml`).

للوضع التجريبي (Mock Zoho كامل — منظمة وهمية بالصناديق العشرين): أنشئ قاعدة
منفصلة `madar_demo`، وعيّن `MODE=demo` و`DATABASE_URL` عليها ثم نفس الأوامر.
نتائجه تُعنون في الواجهة صراحةً كـMock Discovery.

## الاختبارات (PostgreSQL تكاملية)

```bash
# تحتاج قاعدة اختبار: TEST_DATABASE_URL أو postgresql://madar:madar_dev@localhost:5432/madar_test
npm test
```

16 اختبارًا: كل الـMigrations من قاعدة فارغة وإعادة تشغيلها، المستخدمون
والأدوار، توقيع الجلسات، تشفير أسرار الاتصالات وعدم تسريبها من الـAPI،
اكتشاف الـ20 صندوقًا دون تكرار، Alias uniqueness، تعقيم الأدلة والتدقيق،
الصلاحيات ومنع الوصول المتبادل، المزامنة الجزئية وResume وCancellation
وDedup، بقاء الحالة بعد Restart، أمان تخزين المرفقات وتنزيلها المصرّح،
بحث FTS مقيد بالصلاحيات، وHealth check.

## الربط الحقيقي (live)

1. في `.env`: عيّن `MODE=live` والسرّين و`BASE_URL` الصحيح.
2. من `https://api-console.zoho.com` أنشئ **Server-based Application** بـ
   Redirect URI: `{BASE_URL}/oauth/callback`.
3. من لوحة الإدارة → «إضافة اتصال Zoho»: أدخل Client ID/Secret (يُشفّران
   AES-256-GCM في القاعدة، ولا يمران عبر أي محادثة أو ملف نصي).
4. اضغط «ربط OAuth» ووافق **بحساب أدمن المؤسسة** (الاتصال ملك المؤسسة في جدول
   `connections` — لا يتعطل بمغادرة موظف).
5. اضغط «اكتشاف الصناديق»: المنصة تكتشف كل صناديق المؤسسة من Zoho API، تصنّف
   نوع كل صندوق، تفحص قدرات القراءة فعليًا، وتعرض المقارنة مع القائمة المرجعية.
6. اختر **صندوق Pilot واحدًا** وفعّل المزامنة (قراءة فقط) — لا مزامنة شاملة
   قبل قرارك.

## الضمانات

- **قراءة فقط:** لا تعديل، لا تعليم كمقروء، لا حذف، لا نقل، لا Forwarding،
  لا إنشاء حسابات، لا تغيير نوع أي صندوق.
- **منع التكرار:** فهرس مزدوج (معرّف المزوّد + بصمة `Message-ID`) على مستوى
  المنصة، ويشمل ما يصل من مصادر مختلفة (API + أرشيف مستورد).
- **الأدلة:** كل استنتاج كشف محفوظ مع ردود الـAPI الحرفية (بعد التعقيم) في
  `detection_reports` ومعروض في لوحة الإدارة.
- **الفصل بين المسارات:** القراءة الحية (Mail API) ≠ طابور المراجعة
  (Moderation) ≠ استيراد الأرشيف (eDiscovery) — تُعرض بأسمائها ولا تُخلط.
- **الأمان:** OAuth فقط بصلاحيات قراءة، تشفير التوكنات، جلسات HttpOnly،
  سجل تدقيق لكل وصول حساس، صلاحيات لكل موظف على كل صندوق.

## الهيكل

```
madar/
├── server.js                    نقطة التشغيل + التوجيه + جدولة مزامنة الـPilot
├── core/                        النواة (لا تعرف Zoho): db, crypto, auth, audit, env
├── modules/mail/                قسم البريد
│   ├── routes.js                REST API
│   ├── detection.js             محرك الكشف والاكتشاف المؤسسي + المقارنة بالمرجع
│   ├── zoho-client.js           عميل Zoho خام (يرجع الردود الحرفية دون رمي أخطاء)
│   ├── sync.js                  المزامنة (Pilot فقط، قراءة فقط، ≤25 طلب/دقيقة)
│   └── connectors/              الاستراتيجيات: mail-api, ediscovery-import, base
├── public/index.html            الواجهة: بريد + لوحة إدارة واحدة (RTL)
├── scripts/diagnose.js          أداة فحص مستقلة (طوارئ) — نفس منطق detection
├── test/                        mock Zoho + fixtures + 13 اختبارًا
└── docs/COMPANY-ENVIRONMENT.md  توثيق بيئة الشركة (20 صندوقًا مشتركًا)
```
