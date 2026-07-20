# Madar Integration API — الأنظمة المحاسبية فوق الصناديق المشتركة

‏Madar هو طبقة التجريد: الأنظمة الخارجية (محاسبة تستهلك `finance@` / `billing@` /
`tax@`) **لا تتصل بـZoho إطلاقًا** — تستهلك هذه الواجهة بمفتاح آلة.

## المصادقة

- المشرف ينشئ مفتاحًا من «إدارة» ← Integration Keys (أو
  `POST /api/admin/integration-keys` بجسم `{name, mailbox_ids:[...]}`).
- **التدوير**: `POST /api/admin/integration-keys/rotate` بجسم `{key_id}` —
  سرّ جديد لنفس هوية المفتاح: النطاق والمؤشرات تبقى (لا عاصفة إعادة تسليم)،
  والسرّ القديم يموت فورًا. مدقَّق (`admin.integration_key.rotate`).
- إنشاء المفتاح **هو** منح الوصول الآلي: نطاق صناديق صريح لكل مفتاح، مدقَّق
  (`admin.integration_key.create` / `.revoke`).
- السرّ يظهر **مرة واحدة** عند الإنشاء (`mik_…`)، ولا يُخزَّن — hash فقط.
- الاستهلاك: ترويسة `X-Api-Key: mik_…` أو `Authorization: Bearer mik_…`.
  لا جلسات ولا CSRF على هذا المسار. مفتاح مبطَل/مجهول = `401`؛ صندوق خارج
  النطاق = `404` (لا يُفرَّق عن غير الموجود).

## المعرّفات الثابتة

- `mailbox.id` و`messageId` و`occurrenceId` هويات قاعدة بيانات: لا تتغير ولا
  يعاد استخدامها. `messageId` (القانوني) يوحّد نفس الرسالة عبر الصناديق —
  منع التكرار مضمون على مستوى الواجهة والمخطط معًا.

## التدقيق

كل وصول آلي مسجَّل في سجل التدقيق: هوية المستهلك (`key:<id>` — السرّ لا
يُسجَّل أبدًا)، الصندوق، نطاق الرسائل المقروء (أول/آخر occurrence + العدد)،
الإجراء، والوقت. محاولات مفاتيح فاشلة تُسجَّل أيضًا (`integration.auth_failed`)
دون تسجيل السرّ المجرَّب.

## نقاط النهاية

### `GET /api/integration/v1/mailboxes`
صناديق نطاق المفتاح فقط:
```json
[{ "id": 7, "address": "finance@exoticcolors.org", "displayName": "Finance", "type": "shared" }]
```

### `GET /api/integration/v1/mailboxes/{id}/messages`
**غير المقروء** لهذا المستهلك (كل ما بعد مؤشره الدائم). معاملات اختيارية:
`after_id` (تجاوز المؤشر؛ `after_id=0` يعيد التاريخ كاملًا)، `limit` (افتراضي
100، أقصى 500). الترتيب تصاعدي حسب `occurrenceId` — ثابت وقابل للاستئناف.
الهوية الأساسية خارجيًا هي `messageId` (هوية Madar القانونية) — **لا تُكشف
معرّفات المزوّد ولا آلية النسخ الداخلية أبدًا**؛ `occurrenceId` هو معرّف موضع
التسليم الذي يخاطبه المؤشر.
```json
{ "mailboxId": 7, "cursorUsed": 0, "nextCursor": 75531, "count": 1,
  "messages": [{
    "messageId": 75530, "occurrenceId": 75531,
    "rfcMessageId": null, "threadId": "…", "direction": "in",
    "subject": "Invoice 42", "snippet": "…",
    "from": { "address": "vendor@example.com", "name": "Vendor" },
    "to": "finance@exoticcolors.org", "cc": "",
    "sentAt": "2026-07-19T22:49:27.433Z", "receivedAt": "2026-07-19T22:49:27.433Z",
    "folder": "Live (وارد موجّه)", "hasAttachments": true,
    "attachments": [{ "id": 12, "name": "invoice.pdf", "size": 12345, "mime": "application/pdf", "quarantined": false }]
  }] }
```

### `POST /api/integration/v1/mailboxes/{id}/cursor`
إقرار الاستهلاك: `{ "last_occurrence_id": 75531 }`. المؤشر **رتيب** (GREATEST) —
إقرار أدنى بالخطأ لا يعيد رسائل مستهلكة. لكل مفتاح مؤشره المستقل لكل صندوق.

### `GET /api/integration/v1/attachments/{id}`
بايتات المرفق. النوع من فحص البايتات لا من ادعاء المزوّد؛ المرفق المحجور
(نوع معلن ≠ محتوى مكتشف) يرفض بـ`423`.

## نمط الاستهلاك الموصى للمحاسبة

```bash
# poll (كل دقيقة مثلًا): الجديد فقط، ثم إقرار
curl -s -H "X-Api-Key: $KEY" "$MADAR/api/integration/v1/mailboxes/7/messages"
# ... process messages, download attachments ...
curl -s -X POST -H "X-Api-Key: $KEY" -H 'Content-Type: application/json' \
  -d '{"last_occurrence_id": 75531}' "$MADAR/api/integration/v1/mailboxes/7/cursor"
```
فشلتَ قبل الإقرار؟ الاستدعاء التالي يعيد نفس الرسائل — exactly-once لموضعك.

## لماذا لا بوابة IMAP الآن (قرار موثق)

واجهة REST بمؤشر دائم تغطي حالة الاستهلاك المحاسبي بالكامل (جديد/غير مقروء،
هوية ثابتة، مرفقات، عدم تكرار) بسطح هجوم أصغر بكثير من خادم IMAP كامل
(TLS/AUTH/IDLE/حالات صناديق). إن ظهر مستهلك يشترط IMAP حرفيًا، النموذج الحالي
(معرّفات ثابتة + مؤشرات) يُسقَط على UID/UIDVALIDITY مباشرة — تُبنى البوابة
حينها كمحوّل فوق هذه الواجهة نفسها، لا كمسار بيانات ثانٍ.
