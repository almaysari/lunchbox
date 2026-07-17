# قرارات تقنية

## قاعدة التشغيل: PostgreSQL (المتطلب المعتمد) — وسجل مرحلة SQLite المؤقتة

**PostgreSQL هو المتطلب المعتمد** لقاعدة تشغيل منصة مدار في جميع الأوضاع
(development / demo / live / production / integration tests).

استخدام SQLite في النسخ الأولى كان **مرحلة نموذج أولي مؤقتة** اختارها المنفّذ
لتسريع البناء بصفر تبعيات، ولم تكن متوافقة مع متطلب الإنتاج المعتمد، وقد
**استُبدلت بالكامل** في 2026-07-16: لا يوجد اليوم أي `node:sqlite` ولا ملفات
قواعد بيانات محلية في أي مسار تشغيل، والاختبارات التكاملية نفسها تعمل على
PostgreSQL حقيقي (انظر `docs/POSTGRES-SCHEMA-VERIFIED.md`).

## Migrations: استراتيجية Forward-only

لا Rollback تلقائي. كل migration يعمل داخل Transaction واحدة مع تسجيل في
`schema_migrations` (اسم + checksum). تعديل migration مطبّق يفشل بفحص الـchecksum؛
أي إصلاح يُشحن كـmigration جديد. سبب القرار: rollback scripts نادرًا ما تُختبر
بواقعية وتخلق مخاطر فقدان بيانات أكبر من المشكلة التي تحلها؛ استعادة الكوارث
تكون من نسخ PostgreSQL الاحتياطية.

## سرّان منفصلان

`MADAR_ENCRYPTION_KEY` (تشفير التوكنات والأسرار at-rest بـAES-256-GCM) منفصل عن
`MADAR_SESSION_SECRET` (توقيع كوكيز الجلسات HMAC-SHA256) — تسرّب أحدهما لا
يكسر الآخر، وكلاهما ≥ 32 بايت hex بتحقق صارم عند الإقلاع ويرفض تساويهما.

## كلمات المرور

scrypt بمعاملات صريحة (N=2^15, r=8, p=1) بصيغة `scrypt$N$salt$hash`.
لا يوجد أي admin افتراضي: `npm run create-admin` هو المسار الوحيد، لا يطبع
كلمة المرور ولا يقبل أقل من 12 حرفًا.

## تخزين المرفقات

طبقة تجريد (`core/storage.js`): مفاتيح عشوائية 24 بايت (غير قابلة للتخمين،
بلا امتداد)، خارج `public/` بأذونات 0600/0700، منع Path Traversal بالتحقق من
صيغة المفتاح، حد حجم، SHA-256 محفوظ، وكل قراءة تمر عبر مسار API مصرّح
ومسجّل في التدقيق. إضافة S3-compatible لاحقًا = تنفيذ نفس الواجهة
(put/getStream/exists) خلف `MADAR_STORAGE`.


## الأسرار الثلاثة وتدوير مفتاح التشفير (2026-07-17)

- `MADAR_ENCRYPTION_KEY` (+ `MADAR_ENCRYPTION_KEY_V2...` للتدوير): تشفير
  at-rest بـAES-256-GCM. كل قيمة مشفرة تحمل رقم نسخة مفتاحها (`k1:`, `k2:`)،
  والكتابات الجديدة تستخدم أحدث نسخة، والقديمة تبقى قابلة للفك ثم يعاد
  تشفيرها (`reencrypt`). جدول `connections` يسجل `encryption_key_version`.
- `MADAR_SESSION_SECRET`: توقيع كوكيز الجلسات HMAC-SHA256.
- `MADAR_CSRF_SECRET`: توكنات CSRF (double-submit مربوطة بجلسة المستخدم).
- تخزين قيم Zoho: `client_id` نص عادي (معرّف عام)؛ `client_secret` و
  `refresh_token` مشفران at-rest؛ `access_token` في الذاكرة فقط ولا يُخزن
  ولا يُسجل أبدًا. تحديث الـrefresh token محمي بقفل PostgreSQL استشاري
  (`pg_advisory_xact_lock`) يمنع سباقات التحديث بين العمليات المتوازية.
