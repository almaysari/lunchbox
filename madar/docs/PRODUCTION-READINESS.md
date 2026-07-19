# تقرير جاهزية الإنتاج — Live Sync (Madar Mail)

**الحالة**: `Architecture-Reviewed, Redesigned, CI-Proven — Pending Real-Tenant Soak`
**قاعدة الحكم**: لا يُعلَن "Production Ready" نهائيًا إلا بعد نجاح فحص القبول على
التنانت الحقيقي لعدة أيام (`scripts/livesync-acceptance.js` — القسم 9). كل ما
عدا ذلك في هذا التقرير مثبت بكود واختبارات على PostgreSQL حقيقي في CI.

---

## 1) Architecture Review — مراجعة الطبقات الـ28

| # | الطبقة | التصميم الحالي | الحكم |
|---|--------|----------------|-------|
| 1 | Startup | فحص DB + storage ثم استرداد الأعطال (`recoverStaleJobs`) ثم بدء الـworker؛ فشل أي تبعية = خروج صريح | سليم |
| 2 | Worker lifecycle | worker داخل العملية الرئيسية؛ نبضة DB (`sync_worker_heartbeat`) تعلن الحياة عبر العمليات؛ إيقاف نظيف عند SIGTERM | **أُعيد تصميمه** (كان process-local) |
| 3 | Scheduler | حلقة `setTimeout` بلا تراكب؛ **جدولة ساخن/بارد للمجلدات**: Inbox/Sent كل دورة، الباقي كل `MADAR_COLD_FOLDER_INTERVAL_SEC` (900ث) أو أثناء backfill | **أُعيد تصميمه** (كل المجلدات كل دورة كان يتجاوز زمن الدورة) |
| 4 | Queue | لا queue خارجي — `sync_jobs` في PostgreSQL هي الـqueue (حالة، مؤشر، تقدّم) | سليم ومقصود (أقل مكونات = أقل أعطال) |
| 5 | Job locking | فهرس فريد جزئي `idx_sync_jobs_one_active` — تشغيلان متزامنان: واحد يفوز حتميًا | سليم (مُختبَر) |
| 6 | Recovery | ثلاث طبقات: إقلاع (`recoverStaleJobs`)، كل دورة (`reconcileStale` ببوابة عمرية 15د)، سياسة Docker `restart: unless-stopped` | **أُكمل** (كان إقلاعًا فقط) |
| 7 | OAuth | Self-client + refresh token مشفّر AES-256-GCM؛ لا secrets في logs/git | سليم |
| 8 | Token refresh | **client واحد لكل connection + access token مثبَّت مشفّرًا في DB مع expiry** — تجديد ≈ 1/ساعة/اتصال بدل تجديد لكل صندوق كل دورة؛ قفل استشاري يمنع سباق التجديد عبر العمليات | **أُعيد تصميمه** (token churn كان يضرب حدود Zoho) |
| 9 | Folder discovery | `listFolders` كل دورة + upsert؛ فشلها = تشخيص typed بمرحلة `list_folders` | سليم |
| 10 | Cursor management | `sync_state` لكل (mailbox, folder): `next_start`, `backfill_done`, `last_sync_at` — يبقى عبر restart | سليم (مُختبَر) |
| 11 | Incremental sync | مسح **الصفحة الأحدث كاملة** كل دورة — لا اعتماد على ترتيب Zoho غير الموثّق | **أُصلح** (break-on-first-duplicate كان يُسقط بريدًا جديدًا) |
| 12 | Backfill | متابعة من المؤشر، صفحات محدودة لكل دورة (`maxPages`)، لا يُهجر مجلد أبدًا | سليم (مُختبَر) |
| 13 | Deduplication | `ON CONFLICT DO NOTHING` على مفتاحين (dedup_hash الكنسي + (mailbox, canonical) للنسخ) — حتمي تحت التوازي | سليم (مُختبَر بـ20 إدراجًا متوازيًا) |
| 14 | Canonical Identity | fp3 من حقول Zoho الحقيقية (from/SENT-second/subject/to/cc) + RFC oracle جنائي + مقاييس تصادم | سليم (v3، بانتظار تحقق أرشيف الإنتاج) |
| 15 | Database writes | معاملة لكل رسالة؛ ترتيب أقفال ثابت (canonical → occurrence) = لا deadlock؛ rollback لليتيم | سليم (مُختبَر) |
| 16 | Routing | نسخة العضو → صندوق المجموعة بنفس الكنسي؛ سياق التوجيه في التشخيص | سليم (بحدود موثّقة — قسم 10) |
| 17 | Permissions | لا قراءة محتوى دون منح صريح `can_view_messages` حتى للأدمن | سليم (مُختبَر) |
| 18 | Visibility | `visibility-trace` (7 فحوص + حكم حاسم) + زر منح ذاتي | سليم |
| 19 | Diagnostics | صف typed لكل دورة/صندوق: مرحلة، endpoint، HTTP/SQL/transport كامل (`kind/code/errno/syscall/hostname/causeChain/stack`)، traceId | سليم |
| 20 | UI state | حالة الـworker من النبضة (running/stale/off)؛ حالات الصندوق تُصحَّح تلقائيًا | سليم |
| 21 | Error handling | أخطاء typed؛ لا "internal error" — errorId + سبب حقيقي + traceId | سليم |
| 22 | Retry | backoff أسّي لكل صندوق (حتى 30د) لا يعطّل بقية الصناديق | سليم (مُختبَر) |
| 23 | Network failures | HTTP 0 مصنَّف كاملًا (dns/tls/refused/reset/timeout/unreachable)؛ الدورة تفشل نظيفًا وتُعاد بالـbackoff | **أُصلح** (كان معتمًا) |
| 24 | Rate limits | pacing على مستوى الـclient المشترك (لكل connection ≈ حدود Zoho الفعلية) + مهلة لكل طلب | **تحسّن** (كان لكل client جديد، أي بلا فعالية عبر الصناديق) |
| 25 | Concurrent sync protection | فهرس فريد جزئي + `checkpoint` مخنوق (`MADAR_CHECKPOINT_MS`) للإيقاف/الإلغاء | سليم (مُختبَر) |
| 26 | Restart recovery | مؤشر دائم + استرداد إقلاع + `reconcileStale` كل دورة + سياسة Docker restart | سليم (مُختبَر) |
| 27 | Production logging | دورات الـworker في `sync_worker_cycles` (source: worker/cli/manual)؛ **تشذيب احتفاظ** كل ~6س (`MADAR_RETENTION_DAYS`=14) — الـaudit لا يُشذَّب أبدًا | **أُكمل** (كان نموًّا بلا حد) |
| 28 | Health monitoring | `/healthz` يعرض worker: running/stale/lastTick + stuckJobs + stuckMailboxes (أرقام فقط) | **أُكمل** |

## 2) Root Cause Analysis — لماذا كان كل إصلاح يكشف مشكلة جديدة؟

سلسلة الأعطال السابقة (syncing العالق، "worker OFF" الكاذب، البريد المخفي،
HTTP 0 المعتم، البريد الجديد الساقط) لم تكن أعطالًا مستقلة؛ لها **أربعة جذور
معمارية** عولجت الآن بإعادة تصميم لا بترقيع:

1. **حالة حرجة في ذاكرة عملية واحدة** (worker enabled، access token، backoff):
   أي قارئ في عملية أخرى يرى العدم، وأي restart يفقدها → "OFF" الكاذب،
   token churn، فقدان الـbackoff. **العلاج**: كل حالة يقرؤها أكثر من طرف صارت
   في PostgreSQL (نبضة، دورات، token مشفّر، مؤشرات) — الذاكرة أصبحت cache فقط.
2. **افتراضات غير موثّقة عن Zoho** (ترتيب الرسائل، صلاحية القراءة للأدمن، وجود
   RFC Message-ID): كل افتراض سقط لاحقًا على التنانت الحقيقي. **العلاج**:
   الصحة لم تعد تعتمد على أي سلوك غير موثّق (مسح الصفحة كاملة، fp3 من حقول
   مثبتة، تشخيص transport بدل الافتراض).
3. **مسارات فشل بلا مالك** (دورة تموت في المنتصف، رفض promise غير معالج):
   كانت تترك حالة عالقة تتطلب تدخلًا يدويًا. **العلاج**: تصميم crash-only —
   استرداد ثلاثي الطبقات + حراس العملية + سياسة إعادة تشغيل Docker؛ لا يوجد
   عطل يُبقي النظام في حالة تحتاج يدًا بشرية.
4. **لا اقتصاد موارد للمدى الطويل** (جداول تنمو بلا حد، تجديد token لكل دورة،
   كل المجلدات كل دورة): يعمل أيامًا ثم يتدهور. **العلاج**: احتفاظ مجدول،
   token واحد/ساعة، جدولة ساخن/بارد.

## 3) Failure Mode Analysis — ماذا يحدث عند كل عطل؟

| العطل | السلوك الآن | التعافي | يدوي؟ |
|-------|-------------|---------|-------|
| موت العملية الرئيسية (OOM/uncaught) | log كامل + heartbeat off + exit(1) | Docker يعيد التشغيل؛ الإقلاع يستأنف من المؤشرات | **لا** |
| رفض promise غير معالج | log كامل بالـstack + استمرار الخدمة | لا انقطاع | **لا** |
| SIGTERM (docker stop/deploy) | إيقاف worker + drain + إغلاق DB | إقلاع نظيف تالٍ | **لا** |
| دورة تموت في منتصفها | job يبقى 'running' حتى بوابة 15د ثم يُوقَف مؤقتًا ويُستأنف تلقائيًا في الدورة التالية | `reconcileStale` كل دورة | **لا** |
| انقطاع الشبكة إلى Zoho | فشل transport مصنَّف (dns/tls/...)؛ backoff أسّي لكل صندوق؛ بقية الصناديق تستمر | تلقائي عند عودة الشبكة | **لا** |
| انتهاء access token | تجديد واحد تحت قفل استشاري، مثبَّت للجميع | تلقائي | **لا** |
| انتهاء/سحب refresh token | فشل دورة بسبب واضح في التشخيص + status الاتصال | **نعم — بطبيعته**: إعادة تفويض OAuth من الأدمن (لا يوجد حل تقني آخر) |
| PostgreSQL يسقط | فشل الدورات نظيفًا؛ healthz غير جاهز | تلقائي عند عودة DB (compose يعيد تشغيله) | **لا** |
| امتلاء القرص بالتشخيص | لا يحدث: احتفاظ 14 يومًا للجداول التشغيلية | تشذيب كل ~6س | **لا** |
| rate limit من Zoho | pacing مشترك لكل connection + backoff عند 429/transport | تلقائي | **لا** |

## 4) Reliability / Recovery / Stress / Long-running Tests

42/42 اختبارًا على PostgreSQL حقيقي (الـmock الوحيد هو خادم Zoho HTTP — لأن CI
لا يملك تنانتك). الاختبارات الحاسمة:

| الخاصية | الاختبار |
|---------|----------|
| Restart أثناء المزامنة → استئناف | `crash recovery: running jobs become paused (resumable) on startup` |
| لا jobs عالقة / لا mailbox عالق | `new mail is captured … a dead cycle never stalls a box forever` + `mini-soak` |
| Race conditions | `concurrent sync start: exactly one job wins` + `concurrency: 20 parallel inserts — no deadlock, one canonical` |
| عدم التكرار (live↔archive↔routing) | `live sync convergence (zero duplication)` + `canonical fingerprint v3` |
| اقتصاد الـtoken وتجديد الانتهاء | `OAuth token economy: … refresh only on expiry` (دورتان ≤ تجديد واحد؛ عملية جديدة = صفر تجديد؛ انتهاء = تجديد واحد بالضبط) |
| جدولة المجلدات | `folder scheduler: inbox/sent hot; cold rotate; backfill never abandoned` |
| الاحتفاظ | `retention: … pruned; audit is NEVER pruned` |
| صحة الـworker عبر العمليات | `worker status is read from the DB heartbeat (not a process singleton)` |
| تشخيص transport | نفس الاختبار: `ZohoApiError` يحمل kind/code/syscall/hostname + stack |
| Soak مصغّر | `mini-soak: 25 consecutive ticks — no stuck state, bounded memory maps` |

**Stress/Long-running الحقيقيان** لا يُثبتان في CI بطبيعتهما — أداتهما القسم 9.

## 5) Security Review

- Secrets: مشفّرة AES-256-GCM بمفاتيح مُدارة بالإصدارات (access token الجديد
  كذلك)؛ لا secrets في logs/تشخيص/تقارير؛ `verify:security` + gitleaks على كامل
  التاريخ في CI.
- المحتوى: سياسة المنح الصريح تمنع حتى platform_admin من القراءة دون grant
  (مُختبَر)؛ الـaudit بلا مواضيع/أجساد؛ 404 موحّد للموارد غير المصرّح بها.
- الحقن: كل SQL معلمي؛ القيم المُدرجة في interval literals مقيّدة `Number()`.
- التشخيص: عيّنات الاستجابة أسماء حقول وأكواد فقط — لا PII.

## 6) Performance Review

- **API volume**: الجدولة الساخنة/الباردة تخفض طلبات الدورة من
  `folders × mailboxes` إلى `~2 × mailboxes` في الحالة المستقرة (~5× أقل مع 11
  مجلدًا) — زمن الدورة صار محدودًا تحت الفاصل الافتراضي.
- **DB load**: خنق checkpoint من SELECT لكل رسالة إلى 1/ثانية/job؛ فهارس على
  كل مسارات القراءة الساخنة؛ الاحتفاظ يمنع تضخم الجداول التشغيلية.
- **Token endpoint**: من O(mailboxes × cycles) إلى ~1/ساعة/اتصال.
- **الذاكرة**: كل الخرائط داخل العملية مقيّدة (perMailbox يُشذّب لغير المؤهل،
  `_checkpointAt` يُحذف عند نهاية الـjob) — مُختبَر في mini-soak.

## 7) ما الذي أُعيد تصميمه (لا ترقيع)

1. **طبقة الـtoken**: cache لكل connection + تثبيت مشفّر في DB (migration 010).
2. **جدولة المجلدات**: ساخن/بارد بدل الكل-كل-دورة.
3. **نموذج الأعطال للعملية**: crash-only + حراس + إيقاف نظيف.
4. **الملاحظة التشغيلية**: نبضة + دورات مصنّفة المصدر + احتفاظ — بدل حالة ذاكرة
   وسجلات بلا حد.

## 8) Remaining Risks — بصراحة

1. **بيئة الشبكة عندك**: `list_folders` فشل بـHTTP 0 على خادمك — هذا **خارج
   الكود** (egress/DNS/TLS من الحاوية إلى Zoho). الأداة تصنّفه الآن؛ إن ظهر
   `dns` أو `refused` فالحل في سياسة شبكة الحاوية لا في Madar.
2. **حدود التوجيه للصناديق المشتركة**: نسخة العضو تُلتقط من to/cc فقط — بريد
   وصل للمجموعة عبر BCC أو قوائم لا يُوجَّه حيًّا (يصل لاحقًا عبر الأرشيف).
   قيد مصدره Zoho (لا API حي للمجموعات — مُثبت في DECISIONS.md).
3. **Canonical v3 على أرشيف الإنتاج**: بانتظار أول تصدير eDiscovery حقيقي
   (`scripts/validate-fp3.js`) — الحالة موثّقة منذ اعتماد v3.
4. **حدود Zoho غير المنشورة**: pacing افتراضي 25 RPM محافظ؛ عدّله بـ
   `MADAR_MAX_RPM` إذا وثّقت Zoho حدًّا أعلى لمؤسستك.

## 9) بوابة الاعتماد النهائية — التشغيل المتواصل على التنانت الحقيقي

هذا هو الدليل الذي اشترطتَه، وأنا لا أستطيع توليده بالنيابة عنك لأنه يتطلب
نظامك الحي. الأداة تجمعه تلقائيًا:

```bash
# 1) شغّل النظام (رسميًا عبر Docker)
docker compose up -d --build

# 2) (اختياري لكن حاسم) أرسل بريدًا حقيقيًا لصندوق مُزامَن بعنوان فريد مثل:
#    "ACCEPT-<أي رمز> فحص القبول"

# 3) شغّل فحص القبول عدة أيام — يكتب الأدلة ويحكم بنفسه:
docker compose exec -d app node scripts/livesync-acceptance.js \
  --hours 72 --canary "ACCEPT-<الرمز>" 

# 4) بعد انتهائه:
docker compose exec app cat data/acceptance-report.json
```

يفحص كل دقيقة ويحكم PASS/FAIL على: حياة الـworker بلا انقطاع، صفر jobs عالقة،
صفر mailboxes عالقة، صفر تكرارات (occurrences وcanonicals)، استقرار ذاكرة
عملية الـworker (<25% نموًّا)، اقتصاد الـtoken (~1/ساعة)، صحة النقل، والتقاط
الـcanary الحقيقي بلا تكرار مع زمن الوصول. **PASS هنا = Production Ready
بالتعريف الذي طلبته.** أي FAIL يأتي مع الدليل المصنَّف الذي يحدد الطبقة.
