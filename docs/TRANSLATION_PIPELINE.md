# خط لوله ترجمه فارسی CTI

این مخزن داده upstream MITRE ATT&CK و CAPEC را دست نخورده نگه می‌دارد و خروجی فارسی را فقط زیر `translated/fa/` می‌سازد. خروجی معتبر باید دو زبانه باشد: فیلد اصلی انگلیسی باقی می‌ماند و متن فارسی در فیلد هم‌نام با پسوند `_fa` قرار می‌گیرد.

## معماری

1. داده upstream از ریشه‌های `enterprise-attack/`، `mobile-attack/`، `ics-attack/`، `pre-attack/` و `capec/` خوانده می‌شود.
2. ابزار `scripts/seed_translation_cache_from_existing.py` ترجمه‌های سالم موجود را با تطبیق `id` شیء STIX و مسیر فیلد از خروجی قبلی استخراج و در SQLite ذخیره می‌کند.
3. ابزار `scripts/translate_cti_to_persian.py` در حالت `--mode suffix` خروجی را از روی داده upstream بازتولید می‌کند.
4. گزینه `--strip-existing-suffixes` هر `*_fa` موجود در ورودی را قبل از اعمال ترجمه پاک می‌کند تا خروجی فقط از فیلدهای انگلیسی و cache معتبر ساخته شود.
5. نشانه‌های حساس مانند `(Citation:...)`، `<code>...</code>`، URLها، شناسه‌های STIX و شناسه‌های ATT&CK پیش از ترجمه placeholder می‌شوند. پس از ترجمه، اگر placeholder یا شمارش نشانه‌ها تغییر کرده باشد، آن ترجمه رد می‌شود.
6. واژه‌نامه قابل ویرایش `data/glossary_fa.json` پیش از ترجمه ماشینی اعمال می‌شود. اصطلاحات تثبیت‌شده و نام‌هایی که نباید ترجمه شوند از همین مسیر محافظت می‌شوند.
7. `scripts/validate_translations.py` خروجی را برای CI بررسی می‌کند: بازنویسی انگلیسی، نبود فارسی در `*_fa`، یکسان بودن `*_fa` با منبع، mismatch نشانه‌ها، placeholderهای باقی‌مانده، و پوشش به تفکیک دامنه/نوع.
8. `scripts/fa_text.py` بعد از ترجمه ماشینی، متن فارسی را اصلاح و کیفیت آن را بررسی می‌کند (بخش «کاهش ترجمه تحت‌اللفظی» در پایین).

## کاهش ترجمه تحت‌اللفظی (اکتبر ۲۰۲۶)

### تشخیص

مقایسه متن انگلیسی و ترجمه موجود (`scripts/mine_glossary_candidates.py` به‌علاوه هم‌ترازی EN/FA روی باندل‌ها) نشان داد که گوگل بیشتر عبارت‌های چندکلمه‌ای را درست ترجمه می‌کند، مثل «کلید رجیستری»، «حرکت جانبی» و «ترافیک شبکه». خطاها روی چند ده مفهوم مشخص متمرکز است:

| انگلیسی | خروجی گوگل | اصلاح |
|---|---|---|
| adversary | دشمن / مخالف / حریف | مهاجم |
| persistence | پایداری / تداوم | ماندگاری |
| legitimate | قانونی (= legal) | مشروع |
| compromised host | میزبان در معرض خطر (= at risk) | میزبان نفوذشده |
| compromise (اسم) | سازش (= توافق) | نفوذ |
| privilege escalation | افزایش امتیاز | ارتقای سطح دسترسی |
| payload | بار / بارهای | محموله |
| exfiltration | استخراج (= extract) | برون‌بری |
| encoding / base64 | رمزگذاری (= encryption) | کدگذاری |
| search order hijacking | ربودن سفارش جستجو | ربایش ترتیب جستجو |
| API call | تماس (= تماس تلفنی) | فراخوانی |
| artifacts | مصنوعات | آثار |
| exploit (آسیب‌پذیری) | سوءاستفاده | بهره‌برداری |
| web shell / shellcode | پوسته وب / کد پوسته | وب‌شل / شل‌کد |
| Sandworm Team و دیگر نام‌ها | تیم کرم شنی | Sandworm Team (انگلیسی) |

علاوه بر این، placeholder قدیمی `[[[CTI_PRESERVE_n]]]` شبیه کد ویکی است. گوگل آن را به `[[رده:...]]` تبدیل می‌کرد و در بعضی موارد متن کاملاً بی‌ربط می‌ساخت (مثلاً «آیات و روایات...» وسط توضیح DoS). در باندل enterprise/mobile/ics، ۲۸۷۸ رشته از ۳۳۲۱۷ چنین خرابی‌ای داشت.

### راه‌حل: اصلاح ورودی و خروجی ماشین ترجمه، نه ترجمه دوباره همه‌چیز

1. **اصلاح بعد از ترجمه، وابسته به متن انگلیسی** (`fa_fixes` در `data/glossary_fa.json`): هر قاعده فقط وقتی اعمال می‌شود که اصطلاح انگلیسی (`match`) در متن منبع باشد و `unless_source` نباشد. مثلاً «قانونی» فقط وقتی به «مشروع» تبدیل می‌شود که منبع legitimate داشته باشد و legal/law نداشته باشد. cache همیشه خروجی خام ماشین را نگه می‌دارد، پس با هر بار تغییر قواعد و اجرای `--cache-only`، کل خروجی بدون ترجمه دوباره بهتر می‌شود.
2. **نرمال‌سازی فارسی**: ی/ک عربی، نیم‌فاصله برای «می» و «ها/های»، و واژه‌های مرکب (نرم‌افزار، آسیب‌پذیری، جمع‌آوری و...). بخش‌های محافظت‌شده (code، citation، لینک، URL، شناسه) هرگز دست نمی‌خورند.
3. **کاهش placeholderها**:
   - `--glossary-strategy post` (پیش‌فرض): اصطلاحات glossary دیگر placeholder نمی‌شوند. فقط `protected_terms` و نام‌ها ماسک می‌شوند.
   - `--segment` (پیش‌فرض): citationهای انتهای جمله قبل از ارسال جدا و بعد سر جایشان برگردانده می‌شوند. هر جمله در یک خط فرستاده می‌شود، ولی کل متن همچنان در یک درخواست است.
   - `--mask-extras` (پیش‌فرض): لینک markdown به‌صورت یکجا، کلید رجیستری، مسیر فایل و نام فایل‌های اجرایی ماسک می‌شوند.
   - `--placeholder-style legacy|caps|tag`: شکل placeholder. پیش‌فرض `tag` (یعنی `<x id="3"/>`) است، بر اساس تست A/B پایین.
4. **نام‌ها انگلیسی می‌مانند**: نام و aliasهای intrusion-set، malware، tool و campaign خودکار از باندل‌ها استخراج و ماسک می‌شوند (حدود ۱۹۰۰ نام). `name_fa` این اشیا برابر نام انگلیسی است و validator آن را سالم حساب می‌کند. نام‌هایی که کلمه عادی هم هستند در `auto_protect_stix_names.exclude` آمده‌اند.
5. **دروازه کیفیت** (`--quality-gate`، پیش‌فرض): ترجمه‌های cache و ترجمه‌های تازه‌ای که متن ساختگی، تکرار بی‌معنی، کد ویکی یا نسبت طول غیرعادی دارند رد می‌شوند. با `--quality-report rejected.jsonl` فهرست آن‌ها برای بازبینی ذخیره می‌شود.
6. **گزارش validator**: بخش جدید «Translation quality» با کدهای `hallucination`، `wiki_markup`، `repetition`، `length_ratio`، `mostly_english` و `glossary_miss:<term>`. با `--max-severe-quality 0` می‌توان CI را سخت‌گیر کرد.

### نتیجه روی داده فعلی enterprise-attack (فقط cache، بدون ترجمه تازه)

| شاخص | رفتار قبلی | پایپ‌لاین جدید |
|---|---:|---:|
| پوشش اشیای نام‌دار | 88.71% | 98.33% |
| `glossary_miss:adversary` | 1437 | 74 |
| `glossary_miss:persistence` | 900 | 74 |
| `glossary_miss:exfiltration` | 782 | 208 |
| `glossary_miss:denial of service` | 45 | 23 |
| زمان بازتولید | ~21s | ~42s |

بخش بزرگی از افزایش پوشش به این خاطر است که نام نرم‌افزارها و گروه‌ها طبق سیاست انگلیسی می‌مانند. ترجمه تازه‌ای انجام نشده است.

ترجمه‌هایی که در seed به‌خاطر خرابی کنار گذاشته شدند باید دوباره ترجمه شوند. در enterprise حدود ۶۰۰۰ رشته یکتا (حدود ۱.۷ میلیون کاراکتر) است که بیشترش relationship description (حدود ۷۵۰ هزار) و attack-pattern description (۳۶۵ مورد، حدود ۶۲۰ هزار) است.

### نتیجه تست A/B (۲۱ اکتبر ۲۰۲۶، google_public، ۱۲۰ توضیح ATT&CK)

| پیکربندی | سالم ماندن placeholderها | خطای جدی | glossary miss |
|---|---:|---:|---:|
| `legacy` + placeholder برای glossary، بدون segment (رفتار قبلی) | 56.7% | 0% | 0 |
| `legacy` + post + segment | 65.0% | 0% | 0 |
| `caps` + post + segment | 99.2% | 0% | 2 |
| **`tag` + post + segment** | **100%** | **0%** | **1** |
| `caps` + inline + segment | 99.2% | 0% | 12 |

- رفتار قبلی تقریباً نیمی از ترجمه‌ها را به‌خاطر placeholder خراب از دست می‌داد. خرابی «[[رده:...]]» از همین‌جا می‌آمد.
- `caps` یک بار شکست خورد: گوگل placeholderی را که فاعل جمله بود حذف کرد.
- `inline` (نوشتن «مهاجمان» در متن انگلیسی قبل از ترجمه) بدتر بود: گوگل واژه فارسی تزریق‌شده را در ۱۱ مورد بازنویسی کرد. برای همین `post` پیش‌فرض ماند.
- بازبینی دستی خروجی `tag` چند خطای جدید نشان داد که به `fa_fixes` اضافه شدند: client→«مشتری» (درستش «کلاینت»)، air-gapped→«شکاف هوا»، Outlook/inbox rule→«قانون» (درستش «قاعده»).

### روند کار پیشنهادی

```bash
# 0) (فقط اگر provider عوض شد) تست A/B دوباره:
python scripts/ab_test_placeholders.py --sample 120 --sleep 0.7

# 1) ساخت cache از ترجمه‌های سالم موجود. ترجمه‌های قدیمی داخل همین فایل‌ها هستند،
#    پس translated-root همان ریشه مخزن است. موارد خراب خودکار کنار گذاشته می‌شوند.
python scripts/seed_translation_cache_from_existing.py --translated-root . --datasets enterprise-attack

# 2) ترجمه فقط موارد باقی‌مانده (پیش‌فرض‌ها: tag + post + segment + quality gate).
#    قابل ادامه است: اگر قطع شد یا 429 گرفت، همین دستور را دوباره اجرا کنید.
python scripts/translate_cti_to_persian.py --mode suffix --strip-existing-suffixes \
  --datasets enterprise-attack --workers 2 --jitter 1.0 \
  --quality-report translated/rejected.jsonl

# 3) اعتبارسنجی
python scripts/validate_translations.py --datasets enterprise-attack

# 4) چرخه بهبود: موارد glossary_miss و rejected.jsonl را بازبینی کنید و
#    به fa_fixes اضافه کنید، سپس فقط با --cache-only بازتولید کنید.
#    برای پیدا کردن اصطلاحات پرتکرار جدید:
python scripts/mine_glossary_candidates.py --top 2000
```

### ساختار یک قاعده در glossary

```json
{
  "source": "legitimate",
  "target": "مشروع",
  "match": "\\blegitimate(?:ly)?\\b",
  "unless_source": "\\blegal|\\blaw\\b",
  "fa_fixes": {"قانونی": "مشروع"},
  "check": true,
  "accept": ["مشروع"]
}
```

- `fa_fixes`: کلید، ترجمه اشتباهی است که ماشین تولید می‌کند و مقدار، شکل درست آن. طولانی‌ترها اول اعمال می‌شوند.
- `check`: اگر منبع اصطلاح را دارد ولی خروجی هیچ‌کدام از `target`/`accept` را ندارد، validator آن را `glossary_miss` گزارش می‌کند.
- ورودی‌های بدون `fa_fixes` اصطلاحات کلاسیک glossary هستند و فقط در `--glossary-strategy placeholder|inline` قبل از ترجمه جایگزین می‌شوند.

## دستور بازتولید خروجی فعلی

ابتدا cache را از خروجی موجود seed کنید:

```bash
python3 scripts/seed_translation_cache_from_existing.py \
  --datasets enterprise-attack
```

سپس خروجی فعلی را بدون ترجمه ماشینی تازه، فقط با cache سالم، بازتولید کنید:

```bash
python3 scripts/translate_cti_to_persian.py \
  --source-root . \
  --output-root translated/fa \
  --datasets enterprise-attack mobile-attack ics-attack pre-attack capec \
  --mode suffix \
  --cache-db .translation-cache/cti_fa.sqlite3 \
  --cache-provider-fallbacks argos_offline \
  --cache-only \
  --strip-existing-suffixes \
  --workers 4 \
  --progress-every 10000 \
  --progress-seconds 30
```

اعتبارسنجی:

```bash
python3 scripts/validate_translations.py \
  --datasets enterprise-attack mobile-attack ics-attack pre-attack capec
```

برای اجرای CI سخت‌گیرتر می‌توان آستانه‌ها را تنظیم کرد، مثلا:

```bash
python3 scripts/validate_translations.py \
  --max-overwritten-objects 0 \
  --max-marker-mismatches 0 \
  --max-nonpersian-fa 0 \
  --max-identical-fa 0
```

## وضعیت قبل و بعد

Baseline قبل از بازسازی روی `enterprise-attack`:

| وضعیت | تعداد |
|---|---:|
| سالم | 89 |
| خراب، با فیلد انگلیسی بازنویسی‌شده | 861 |
| ترجمه‌نشده | 3849 |
| فیلدهای بازنویسی‌شده | 5666 |
| mismatch نشانه‌های محافظت‌شده | 21 |

وضعیت پس از بازسازی روی همه دامنه‌ها:

| شاخص | مقدار |
|---|---:|
| سالم | 7953 |
| خراب، با فیلد انگلیسی بازنویسی‌شده | 0 |
| ترجمه‌نشده | 4324 |
| پوشش کلی اشیاء نام‌دار | 64.78% |
| فیلدهای بازنویسی‌شده | 0 |
| mismatch نشانه‌های محافظت‌شده | 0 |
| placeholder باقی‌مانده | 0 |
| `*_fa` بدون حرف فارسی | 20928 |
| `*_fa` یکسان با متن منبع | 20559 |

تعداد بالای `*_fa` بدون حرف فارسی عمدتا از نام منبع‌های بیرونی، نام ابزارها، شناسه‌ها و نام‌های خاص می‌آید. این موارد گزارش می‌شوند اما در تنظیمات پیش‌فرض باعث شکست validation نمی‌شوند؛ برای سیاست سخت‌گیرانه‌تر از `--max-nonpersian-fa` و `--max-identical-fa` استفاده کنید.

## پوشش فعلی

| دامنه | نوع شیء | ترجمه‌شده / کل | پوشش |
|---|---|---:|---:|
| capec | attack-pattern | 2320 / 2460 | 94.31% |
| capec | course-of-action | 0 / 3569 | 0.00% |
| capec | identity | 4 / 4 | 100.00% |
| enterprise-attack | attack-pattern | 812 / 858 | 94.64% |
| enterprise-attack | campaign | 44 / 46 | 95.65% |
| enterprise-attack | course-of-action | 261 / 268 | 97.39% |
| enterprise-attack | identity | 1 / 1 | 100.00% |
| enterprise-attack | intrusion-set | 131 / 183 | 71.58% |
| enterprise-attack | malware | 382 / 728 | 52.47% |
| enterprise-attack | tool | 40 / 95 | 42.11% |
| enterprise-attack | x-mitre-analytic | 1758 / 1758 | 100.00% |
| enterprise-attack | x-mitre-data-component | 109 / 109 | 100.00% |
| enterprise-attack | x-mitre-data-source | 37 / 38 | 97.37% |
| enterprise-attack | x-mitre-detection-strategy | 698 / 699 | 99.86% |
| enterprise-attack | x-mitre-matrix | 1 / 1 | 100.00% |
| enterprise-attack | x-mitre-tactic | 15 / 15 | 100.00% |
| ics-attack | attack-pattern | 113 / 118 | 95.76% |
| ics-attack | campaign | 9 / 9 | 100.00% |
| ics-attack | course-of-action | 52 / 52 | 100.00% |
| ics-attack | identity | 1 / 1 | 100.00% |
| ics-attack | intrusion-set | 8 / 16 | 50.00% |
| ics-attack | malware | 18 / 30 | 60.00% |
| ics-attack | x-mitre-analytic | 97 / 97 | 100.00% |
| ics-attack | x-mitre-asset | 18 / 18 | 100.00% |
| ics-attack | x-mitre-data-component | 36 / 36 | 100.00% |
| ics-attack | x-mitre-data-source | 17 / 17 | 100.00% |
| ics-attack | x-mitre-detection-strategy | 97 / 97 | 100.00% |
| ics-attack | x-mitre-matrix | 1 / 1 | 100.00% |
| ics-attack | x-mitre-tactic | 12 / 12 | 100.00% |
| mobile-attack | attack-pattern | 187 / 190 | 98.42% |
| mobile-attack | campaign | 2 / 2 | 100.00% |
| mobile-attack | course-of-action | 15 / 15 | 100.00% |
| mobile-attack | identity | 1 / 1 | 100.00% |
| mobile-attack | intrusion-set | 16 / 22 | 72.73% |
| mobile-attack | malware | 64 / 125 | 51.20% |
| mobile-attack | tool | 0 / 2 | 0.00% |
| mobile-attack | x-mitre-analytic | 211 / 211 | 100.00% |
| mobile-attack | x-mitre-data-component | 29 / 29 | 100.00% |
| mobile-attack | x-mitre-data-source | 6 / 6 | 100.00% |
| mobile-attack | x-mitre-detection-strategy | 124 / 124 | 100.00% |
| mobile-attack | x-mitre-matrix | 2 / 2 | 100.00% |
| mobile-attack | x-mitre-tactic | 14 / 14 | 100.00% |
| pre-attack | attack-pattern | 172 / 174 | 98.85% |
| pre-attack | identity | 1 / 1 | 100.00% |
| pre-attack | intrusion-set | 2 / 7 | 28.57% |
| pre-attack | x-mitre-matrix | 0 / 1 | 0.00% |
| pre-attack | x-mitre-tactic | 15 / 15 | 100.00% |

`x-mitre-analytic` در این بازسازی ترجمه ماشینی تازه نگرفته است؛ مقادیر فعلی فقط از cache موجود آمده‌اند. برای اجرای کنترل‌شده بعدی، ابتدا انواع کم‌حجم‌تر مانند `intrusion-set`، `malware`، `tool` و `x-mitre-data-component` را با provider پایدار ترجمه کنید.

## محدودیت‌های شناخته‌شده

- اجرای آنلاین با `google_public` در این محیط با HTTP 429 روبه‌رو شد؛ بنابراین خروجی فعلی عمداً با `--cache-only` ساخته شده است.
- cache قدیمی شامل ترجمه‌هایی با کیفیت محتوایی پایین است؛ نمونه‌هایی مانند «دشمنان» به جای «مهاجمان» ممکن است باقی مانده باشند، چون بازبینی دستی محتوا در این تغییر انجام نشده است.
- ترجمه‌هایی که citation/code/URL/ATT&CK ID یا placeholder خراب داشتند کنار گذاشته شدند؛ این باعث کاهش پوشش برخی فیلدها می‌شود اما از انتشار داده ناسالم جلوگیری می‌کند.
- واژه‌نامه اولیه است و فقط 38 اصطلاح و 39 نام محافظت‌شده دارد. تکمیل آن باید با بازبینی انسانی و بر اساس پرتکرارترین خطاها انجام شود.
- نام‌های خاص، نام منابع خارجی و برخی ابزارها ممکن است در `*_fa` عین انگلیسی بمانند. اعتبارسنج آن‌ها را گزارش می‌کند تا سیاست پروژه درباره ترجمه یا عدم ترجمه آن‌ها روشن بماند.

## به‌روزرسانی با نسخه جدید ATT&CK

1. تغییرات upstream را در ریشه‌های اصلی merge کنید و تعارض‌ها را بدون ویرایش خروجی فارسی حل کنید.
2. cache موجود `.translation-cache/cti_fa.sqlite3` را نگه دارید.
3. در صورت داشتن خروجی فارسی قبلی، cache را دوباره seed کنید:

```bash
python3 scripts/seed_translation_cache_from_existing.py \
  --datasets enterprise-attack mobile-attack ics-attack pre-attack capec
```

4. خروجی فارسی را با دستور بازتولید بالا بسازید.
5. `scripts/validate_translations.py` را اجرا کنید و ابتدا `broken`، `marker mismatches` و `leftover placeholders` را صفر نگه دارید.
6. برای افزایش پوشش، ترجمه ماشینی تازه را به صورت دسته‌های کوچک و با provider پایدار اجرا کنید. اگر از Google Cloud استفاده می‌شود، `--provider google_cloud` و `GOOGLE_TRANSLATE_API_KEY` را تنظیم کنید.
7. پیش از انتشار، `git diff --stat -- enterprise-attack mobile-attack ics-attack pre-attack capec` باید خالی باشد.
