# Recipe JSON schema for HOME COOKBOOK (one object per recipe)

Every recipe object MUST have these keys. Servings are ALWAYS 2 adults. Spice level ALWAYS 0/5.
Units allowed in quantities: g, kg, ml, L, tsp, tbsp, cup, pcs (count). No vague quantities ("some", "a little").
Language: clear simple English. Keep the English dish name EXACTLY as given in the list. Arabic name = correct Arabic name.

{
 "id": "B1" | "S1" | 1..23,
 "name_en": "exact list name",
 "name_ar": "الاسم العربي",
 "cuisine": "Gulf" | "Levantine" | "Egyptian" | "Other",
 "category": "Breakfast" | "Salad" | "Main Course",
 "info": {"prep_time":"15 min","cook_time":"40 min","total_time":"55 min","servings":"2 Adults","difficulty":"Easy|Medium|Hard","equipment":["medium pot with lid","non-stick pan 24 cm", ...]},
 "meat_spec": null | {"type":"Bone-in|Boneless","cut":"Whole|Half|Breast|Thigh|Drumstick|Mixed|Shoulder|Leg|Cubes","skin":"Skin-on|Skinless|n/a","weight":"600 g","preparation":"Whole|Cubes 3 cm|Strips|Pieces (8)","cooking_method":"Grilled|Boiled|Fried|Roasted|Simmered","source_specified": true|false, "note":"if source did not specify, say this is a suggested cut and why"},
   (for lamb use the same keys; cut = Shoulder/Leg/Shank/Neck; add "fat":"moderate" where relevant)
 "spice_note": "one sentence: what chili/hot item the original source had (if any) and what replaces it, or 'Source recipe contains no chili.'",
 "components": [   // 1 component for simple dishes; 2-5 for composite dishes (each component is a full sub-recipe)
   {
    "title": "Part 1 — Grilled Chicken",
    "ingredients": [{"item":"Chicken thighs, bone-in, skin-on","qty":"600 g (4 pcs)","note":"optional note"}],
    "prep": ["Everything to do before turning on the stove, as full sentences."],
    "steps": ["Numbered steps. EACH step names ingredient + quantity + action + pan/pot + heat level + minutes + what success looks like. Example: 'Heat 2 tbsp of oil in a medium pot over medium heat. Add the 1 chopped onion and stir for 5-7 minutes until soft and lightly golden.'"]
   }
 ],
 "timeline": null | ["For composite dishes only: ordered timeline so all parts finish together, e.g. '0:00 Start rice soaking', '0:20 Put chicken in oven', ..."],
 "mistakes": ["Common mistake -> how to avoid, 3-6 items"],
 "serving": ["How to plate and arrange, 2-4 sentences"],
 "safety": ["Safe internal temperature where relevant (chicken 74 C, lamb 70 C), cooling within 1 hour, fridge 2-3 days in closed container, reheat to steaming hot, do not wash raw chicken, separate boards."],
 "source": {"site":"Sayidaty Kitchen","chef":"name or 'Sayidaty Kitchen editorial'","title_ar":"...","url":"direct url","image_source":"to be filled by image step","verification":"Verified (page opened and read) | Partially verified: ...","adapted":"one sentence on what was changed vs the source: scaled to 2 adults, chili removed, boiled egg added, etc."},
 "video": null | {"url":"...","title":"...","channel":"...","language":"English","duration":"12:34 or null","priority":"P4","spicy_warning": true|false, "subtitles":"manual English|n/a"},
 "video_tl": null | {"url":"...","title":"...","channel":"...","language":"Tagalog"}   // second QR; only if provided
}

Scaling rule: scale the Arabic source quantities to 2 adults (main course: ~300-400 g raw meat/chicken for 2; rice 1 to 1.5 cups raw for 2). Keep the source's ratios (rice:liquid, spices). Round to sensible kitchen numbers.
Chili rule: remove every chili/hot item. Replace heat with aroma: for red colour use sweet paprika or tomato paste; for "zing" use lemon or sumac. Black/white pepper max 1/4 tsp per 2 servings. Nando's peri-peri: use a home non-spicy marinade (lemon, garlic, sweet paprika, oregano, olive oil) and say that bottled peri-peri sauce must be checked and is usually hot. Cajun: use a home mix without cayenne (sweet paprika, garlic powder, onion powder, oregano, thyme).
Kabsa vs Bukhari vs Biryani vs Maqluba vs Madhbi vs Salona must each keep their own method and spice mix as in the source.
