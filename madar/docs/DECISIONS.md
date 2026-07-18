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


## سياسات أمنية معتمدة (2026-07-17)

### صلاحيات platform_admin على البريد
الأدوار الإدارية تدير المنصة ولا تقرأ محتوى البريد تلقائيًا: العناوين والنصوص
والمرفقات تتطلب Mailbox Grant صريحًا لكل مستخدم بمن فيهم platform_admin.
الأدوار تمنح الـMetadata والإدارة فقط (سجل الصناديق، أدلة الكشف، مهام
المزامنة). الأدمن يستطيع منح نفسه Grant لكن كل تعديل صلاحيات يسجل في
التدقيق (`admin.grant.set`). لا Dual control في هذه النسخة (منظمة بأدمن
واحد) — يعاد التقييم عند توسع الفريق. التدقيق لا يسجل محتوى البريد أبدًا.

### سياسة 404 (منع التعداد)
مستخدم بلا صلاحية على معرف مورد محدد (mailbox / canonical / occurrence /
attachment / تقرير كشف) يتلقى 404 مطابقًا تمامًا للمعرف غير الموجود.
الاستثناء الموثق: endpoints الإدارية المحمية بالدور تعيد 403 لأنها لا
تكشف وجود أي مورد محدد.

### Canonicalization v2 (canonical_hash_version)
Message-ID أولًا؛ وعند غيابه بصمة من (from | to | cc | subject | timestamp
| hash(snippet) | has_attachments). BCC مستثنى عمدًا (بيانات envelope خاصة
بالـOccurrence). أي تغيير مستقبلي = نسخة جديدة + migration، والصفوف القديمة
تحتفظ بنسختها ولا يعاد دمجها.

### خصوصية الـEnvelope
To/CC/BCC كما رأتها نسخة صندوق معيّن تُخزن على الـOccurrence وتُعرض فقط
لمستخدمي ذلك الصندوق — لا fallback إلى حقول الـCanonical (كان الـfallback
يسرّب CC وأمسكه الاختبار فأزيل).

### Crash Recovery لمهام المزامنة
عند الإقلاع، أي مهمة بقيت `running` بسبب توقف غير نظيف تتحول إلى `paused`
(المؤشر محفوظ → استئناف آمن). اخترنا paused لا queued/failed حتى لا يستأنف
شيء دون قرار مشغّل صريح.

### Migrations في Docker
الـEntrypoint يشغّل الـMigrations قبل التطبيق، والمشغّل يحمل قفل PostgreSQL
استشاري (session-level) — عدة نسخ تبدأ معًا تطبقها مرة واحدة بالضبط
(مُختبر بتشغيلين متزامنين في CI).

### حالة S3
Local Storage: منفذ ومختبر. S3-compatible: **غير منفذ** — العقد مصمم فقط
(`core/storage-s3.js`)، واختيار `MADAR_STORAGE=s3` يوقف الإقلاع برسالة
واضحة ولا يعود تلقائيًا إلى Local. signedUrl في Local يعيد null (غير مدعوم
عمدًا) — كل قراءة تمر حصريًا عبر مسار API المصرّح.

### اعتماد eDiscovery مسارًا وحيدًا لأرشيف الصناديق المشتركة (2026-07-17)

القرار اتُخذ بعد مراجعة الأدمن لمصفوفة الوصول الحرفية (زر «مصفوفة الوصول
لكل Endpoint» — مبنية من `detection_reports` بلا أي نداء جديد): على حساب
الشركة الحقيقي، 34 صندوقًا مغطى و169 صف دليل:

- **صفر** قراءة حية لأي صندوق مشترك (`liveSharedMailboxReadProven: false`).
- 66 محاولة `folders` بمعرفَي mailboxId وzgid لكل الصناديق الـ33 رُفضت
  حرفيًا: `404 "Invalid Input" / "Account id N is invalid"`.
- 33 صندوقًا بلا accountId في `organization/{zoid}/accounts` أصلًا —
  وعائلة رسائل Zoho Mail كلها accounts-scoped، فلا معرف صالح للمحاولة.
- 33 نقطة `groups/{zgid}/messages` أعادت 200 لكنها طابور المراجعة
  الموثّق فقط (المحتوى المعاد = الرسائل المحتجزة حصرًا، يطابق عدادات
  الـModeration) — ليست الأرشيف.
- **الدليل المضاد الحاسم**: النقاط نفسها نجحت كاملة (folders/messages/
  content/attachmentinfo كلها 200 ببيانات) على صندوق المستخدم الأدمن
  الوحيد الذي يملك accountId — أي أن التوكن والنطاقات سليمة، والفشل
  بنيوي في المزوّد لا في التصريح.

النتيجة المعتمدة: القراءة الحية لرسائل الصناديق المشتركة غير ممكنة عبر أي
endpoint رسمي مختبَر؛ مسار الأرشيف الرسمي الوحيد هو تصدير eDiscovery
واستيراده (ZIP/EML) عبر «رفع أرشيف ZIP»، مع طابور المراجعة للمحتجز فقط.
يُعاد النظر تلقائيًا إذا أظهرت مصفوفة لاحقة أي `success` لصندوق مشترك.

### لماذا لا يمكن أتمتة تصدير eDiscovery نفسه (إثبات موثّق، 2026-07-17)

سؤال فُحص بالوثائق الرسمية قبل الإجابة: هل لتصدير eDiscovery أي API أو
واجهة مدعومة قابلة للبرمجة؟ **النتيجة: لا.**

1. **فهرس Zoho Mail API الرسمي** (zoho.com/mail/help/api/) يعدّد فئات
   الـAPI كاملة: Organization, Domain, Users, Mail Policy, Accounts,
   Folders, Labels, Email Messages, Signatures, Threads, Tasks,
   Bookmarks, Notes, Logs — **لا توجد فئة eDiscovery أو Export أو
   Backup** ضمن الواجهات المنشورة.
2. **فضاء نطاقات OAuth الموثّق** (`ZohoMail.*` في using-oauth-2.html
   وscope.html) لا يحتوي أي نطاق `ediscovery` — أي لا يمكن حتى طلب
   تصريح لهذه الوظيفة عبر OAuth.
3. **وثائق eDiscovery نفسها** (email-investigations.html,
   manage-ediscovery.html) تصف التصدير حصريًا كتدفق داخل Admin Console:
   eDiscovery → Investigations/Export → «Export search results» →
   تبويب Exports → تنزيل ZIP/PST — مع **إدخال كلمة مرور الأدمن يدويًا
   عند التصدير** (حاجز بشري مقصود من Zoho)، وخيار كلمة تشفير للملف،
   وتنظيف الملفات المصدَّرة بعد 90 يومًا. لا ذكر لأي endpoint.
4. أتمتة البوابة بجلسة متصفح (تسجيل دخول + MFA + إعادة كلمة المرور)
   ليست «واجهة مدعومة»، وتخالف قيود أمان المشروع (لا كلمات مرور خارج
   OAuth الرسمي) — مرفوضة مبدئيًا.

الحد الأدنى البشري المعتمد: (أ) تشغيل التصدير من بوابة eDiscovery
وتنزيل الـZIP، (ب) اختيار الملف/الملفات في «رفع أرشيف ZIP». كل ما بعد
ذلك آلي بالكامل (فك، تحليل EML، مجلدات، dedup، مرفقات+حجر، فهرسة، تقرير
sync_jobs). الرفع يقبل أجزاء تصدير متعددة دفعة واحدة، وحد الحجم لكل جزء
`MADAR_MAX_UPLOAD_MB` (افتراضي 1024MB) برسالة 413 واضحة.

### تشخيص المزامنة الحية بالأدلة (2026-07-17)

مشكلة: فشل المزامنة كان يظهر كـ"internal error" بلا سياق. السبب الجذري
ليس عطلًا في الجلب بل **غياب طبقة رصد**: معالج 500 في server.js كان يعيد
'internal error' في وضع live ويسجّل الرسالة فقط دون Stack، والموصل يرمي
أخطاء نصية مسطّحة تفقد سياق HTTP.

الإصلاح:
- `sync_diagnostics` (Migration 007): صف لكل دورة مزامنة لكل صندوق يحمل
  المرحلة (connect/list_folders/fetch_messages/db_tx/routing/body/
  attachments/done)، آخر Endpoint، عدّادات القراءة/الإدراج/التجاهل/
  التوجيه، وعند الفشل: نوع الخطأ، الرسالة، **Stack كامل**، وسياق مُصنّف
  (HTTP status/response-sample من ZohoApiError، أو SQLSTATE/constraint من
  أخطاء pg، أو Message-ID/mailbox/decision من التوجيه).
- كل استثناء يحمل الآن `traceId` يظهر في حالة الوظيفة والصندوق والرد.
- معالج 500 لم يعد يعيد 'internal error': يعيد الرسالة الحقيقية (مع تعقيم
  أي بيانات اعتماد) + errorClass + errorId + traceId ويسجّل Stack كاملًا.
- صفحة Diagnostics في اللوحة: آخر دورة لكل صندوق + آخر الأخطاء + عارض
  Stack كامل لكل trace.
- إثبات حي: خادم فعلي، مزامنة جلبت 250 رسالة/83 مرفقًا من Zoho (المحاكي)،
  حُفظت في القاعدة، وظهرت في واجهة البريد بعد منح صريح (سياسة عدم قراءة
  الأدمن بلا Grant تعمل)؛ وصندوق معطوب أظهر السبب الحقيقي + Stack كامل
  عبر /diagnostics بدل 'internal error'.

ملاحظة صدق مسجّلة: messages/view الحقيقي لا يحمل حقل RFC Message-ID، لذا
المزامنة الحية تعتمد بصمة v2؛ الموصل يقبل عدة أسماء للحقل إن توفّر مستقبلًا.

### تشخيص Live Sync وإصلاح الحالة العالقة "syncing" (2026-07-17)

بلاغ «فشل داخلي في Live Sync». التشخيص المبني على أدلة الأدمن (تفاصيل
صندوق m.almaysari@) أبطل فرضية بناء الموصل: الفحص سليم وworkingId موجود
(accountId=8696684000000008002، مجلدات 11، رسائل/محتوى/مرفقات كلها 200).
العَرَض الحقيقي كان الحالة عالقة على "syncing".

**السبب الجذري (Root Cause)**: `recoverStaleJobs` (في modules/mail/sync.js،
أُضيف بـ Live Sync في Commit cf1b72d) كان يعيد المهام العالقة `running`
إلى `paused` عند الإقلاع، لكنه **لا يصحّح صف الصندوق**؛ فأي صندوق تُرك
status='syncing' بإعادة تشغيل غير نظيفة (أو أثناء مزامنة طويلة قُطعت)
يبقى عالقًا بصريًا على "syncing" إلى الأبد.

**التصحيح**: `recoverStaleJobs` يعيد الآن كل صندوق status='syncing' إلى
'ready' مع ملاحظة استئناف، بجانب إيقاف المهمة مؤقتًا. مثبت باختبار.

**طبقة الرصد (لمنع تكرار الغموض)**: جدول sync_diagnostics (Migration 007)
يسجّل لكل دورة: المرحلة (connect/list_folders/fetch_messages/db_tx/
routing/body/attachments/done)، آخر Endpoint، HTTP status، عيّنة استجابة
معقّمة، عدّادات (مقروء/مُدرج/متجاهل/موجّه)، وعند الفشل: نوع الاستثناء،
الرسالة، الـStack الكامل، SQLSTATE/Constraint، وسياق التوجيه. أخطاء Zoho
تُرفع كـ ZohoApiError تحمل endpoint+status+عيّنة. معالج 500 لم يعد يعيد
"internal error": يُصدر errorId متتبَّعًا + السبب الحقيقي المعقّم +
traceId. صفحة «تشخيص المزامنة» تعرض ذلك مع الـStack الكامل لكل trace.

**إثبات حي** (خادم فعلي، وضع demo): مزامنة نجحت (250 رسالة، traceId)،
والرسالة ظهرت في واجهة البريد بعد منح القراءة (subject/from/body)،
وصف sync_diagnostics سجّل outcome=ok stage=done. ثم أُفسد workingId عمدًا
فظهر الفشل الحقيقي حرفيًا: stage=list_folders، HTTP 404،
endpoint=/api/accounts/9999999999/folders، عيّنة «Account id … is invalid»،
وStack كامل عبر zoho-mail-api.js → sync.js → routes.js — بلا أي
"internal error".
