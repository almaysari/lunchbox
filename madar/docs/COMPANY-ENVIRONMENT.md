# بيئة الشركة — البريد على Zoho

> مصدر هذه الوثيقة: Zoho Mail Admin Console → Groups → Shared Mailbox
> (`https://mailadmin.zoho.com/cpanel/home.do#groups/sharedMailbox/list`)
> بتاريخ 2026-07-16، بتأكيد مباشر من مالك المشروع.
>
> **الاستخدام:** مرجع تطوير وتحقق (Validation baseline / Development fixture)
> فقط. المصدر النهائي وقت التشغيل هو Zoho API بعد OAuth الحقيقي — القائمة
> ليست Hardcoded في منطق التطبيق، وتُقرأ من
> `test/fixtures/expected-mailboxes.json` (أو `data/expected-mailboxes.json`
> إن وُضعت نسخة محدثة) لغرض المقارنة في لوحة الإدارة حصرًا.

## الخلاصة

`20 Zoho Shared Mailboxes across exoticcolors.org and thetaurus.world`

جميع عناوين الشركة المطلوب ربطها مصنفة رسميًا داخل Zoho كـ**Shared Mailbox**
(وليست User Mailboxes ولا Distribution Lists ولا حسابات موظفين مستقلة).
لذلك الصندوق المشترك هو **الحالة الأساسية** في معمارية قسم البريد.

## القائمة المرجعية (كما تظهر في لوحة إدارة Zoho)

| # | الاسم | العنوان | Access Level | ملاحظات |
|---|---|---|---|---|
| 1 | Central Relations Mailbox | pro@exoticcolors.org | Everyone | |
| 2 | Central Finance Mailbox | finance@exoticcolors.org | Everyone | |
| 3 | Central HR Mailbox | hr@exoticcolors.org | Everyone | مرشح Pilot |
| 4 | Logistics exotiColors | logistics@exoticcolors.org | Everyone | |
| 5 | Logistics The Taurus | logistics@thetaurus.world | Everyone | نطاق ثانٍ |
| 6 | Departed Employees | former.staff@exoticcolors.org | Everyone | |
| 7 | Central Tax Mailbox | tax@exoticcolors.org | Everyone | |
| 8 | Central Inventory Mailbox | inventory@exoticcolors.org | Everyone | |
| 9 | Central Info Mailbox | info@exoticcolors.org | Everyone | له aliases (+N) |
| 10 | Central Retail Mailbox | retail@exoticcolors.org | Everyone | |
| 11 | Central Legal Mailbox | legal@exoticcolors.org | Everyone | |
| 12 | Central Marketing Mailbox | marketing@exoticcolors.org | Everyone | |
| 13 | AI Commercial Operations | ai@exoticcolors.org | Everyone | |
| 14 | Printer Scan | scan@exoticcolors.org | **Only Moderators** | |
| 15 | Central SMS Mailbox | sms@exoticcolors.org | **Organization Members** | 4 رسائل Moderation |
| 16 | Central Procurement Mailbox | procurement@exoticcolors.org | Everyone | |
| 17 | Central e-commerce Mailbox | e-commerce@exoticcolors.org | Everyone | 1 رسالة Moderation |
| 18 | Time Sheet Submissions | timesheet@exoticcolors.org | Everyone | |
| 19 | Employee Referral Program | referral@exoticcolors.org | **Organization Members** | |
| 20 | POS Operations | pos@exoticcolors.org | Everyone | |

ملاحظات عامة:
- علامة `+N` بجانب بعض العناوين في لوحة Zoho تعني **Aliases** — محرك الكشف
  يلتقطها ويخزنها في `mailbox_aliases`، ولا يسمح أبدًا بتسجيل alias كصندوق ثانٍ.
- أعداد رسائل الـModeration أعلاه لحظية وتتغير — تُقرأ وقت الاكتشاف من
  Groups API وتُعرض كـMetadata، **وليست** جزءًا من أرشيف الصندوق.

## ما يعنيه هذا للتصميم

1. `/api/accounts` وحده لا يكفي أبدًا للاكتشاف — الصناديق تعيش تحت
   `GET /api/organization/{zoid}/groups`.
2. لكل صندوق يجري فحص قدرات فعلي (Folders/Messages/Attachments/Sent) بكل
   معرّف متاح (accountId إن وُجد، وgroupId لتوثيق الرفض الحرفي)، والنتيجة
   الحرفية تُحفظ كدليل.
3. طريقة الربط تُختار من نتيجة الفحص لا من افتراض:
   - قراءة حية مثبتة → `mail_api`
   - لا قراءة حية → `ediscovery_import` للأرشيف (المسار الرسمي) مع عرض
     السبب والدليل، وفتحة جاهزة ليوم يوفر Zoho قراءة حية للصناديق المشتركة.
4. أي تغيير مستقبلي في طريقة الربط لا يفقد البيانات: الرسائل مرتبطة بهوية
   الصندوق في المنصة و`dedup_hash`، لا بالطريقة التي استوردتها.
