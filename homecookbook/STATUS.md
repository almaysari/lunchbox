# HOME COOKBOOK - project status (updated 2026-10-10 20:20 Dubai)

Spec: the 15-section brief (47 recipes: 15 breakfast, 9 salads, 23 mains; 4 deliverables).

## Decisions taken (confirmed by Mohamed)
- Spaghetti with Meatballs: keep meatballs (Einas eats them).
- Chicken Mix = shredded chicken breast sauteed with vegetables.
- Potato = Egyptian pan-fried cubes with cumin.
- Videos: English first; Tagalog kept as a second QR where it exists.
- Servings: 2 adults (spec). A 1-person variant was produced ad hoc for Chicken Biryani.

## Phase 1 - Research & verification: DONE (research/*.json)
- Arabic sources opened and read for all 47 (Sayidaty / Manal / Shamlola; Cookpad only for Pasolla and Cajun chicken; Fatafeat for tabbouleh).
- Not fully verifiable: Manal "mahshi malfouf bil lahm" page unreachable (alt verified); Cookpad Cajun has no oven temp; several Shamlola pages lack quantities (noted per recipe in source.adapted).
- English videos: 34 of 46 found and noembed-verified. None exist for: mains 12, 13, 20, 22; breakfast B5, B6, B8, B11; salads S2, S3, S7, S9 (book will print "English Cooking Video: Not Available").

## Phase 2 - Recipe development: 38 / 47 DONE (recipes/*.json)
- mains_1_8.json, mains_9_16.json, mains_17_23.json: 23 mains complete (template, meat spec, 0/5 spice, composite parts + timeline).
- breakfast.json: 15 complete.
- TODO: salads S1-S9 (research is in research/breakfast_salads.json; write per SCHEMA.md).

## Phase 3 - Images & QR: PARTIAL
- QR generation code exists (sample-biryani-1p.html).
- Photos: real Commons/video photos exist for the 23 mains and 9 salads in cookbook/candidates (picked in cookbook/src/picks.py). TODO: photos for 15 breakfast items.

## Phase 4-6 - Production, QA, delivery: TODO
- Build HTML -> PDF (playwright, works in the container), DOCX (python-docx), XLSX (openpyxl), checklist PDF.
- Deliverables: HOME_COOKBOOK_COMPLETE.pdf, HOME_COOKBOOK_EDITABLE.docx, RECIPE_SOURCE_INDEX.xlsx, RECIPE_REVIEW_CHECKLIST.pdf.

## How to resume cheaply
1. Salads: one agent, input research/breakfast_salads.json (S1-S9) -> recipes/salads.json.
2. Breakfast photos: run candidates collector for B1-B15 via GitHub Actions (no tokens), pick by eye.
3. Renderer: one deterministic Python script reads recipes/*.json and emits all 4 files. No agents.
