CTI

این مخزن شامل MITRE ATT & CK&reg؛ و CAPEC & Trade; مجموعه داده های بیان شده در STIX 2.0.
و یا از آن بهره مند شوید.

اگر شما به دنبال ATT & CK در STIX 2.1 هستید، لطفاً ببینید که [KEEP_0] مخزن GitHub
هر دو MITRE /CTI (این مخزن) و داده های حمله شامل بهبود کیفیت زندگی در MITRE / CK جدید برای آینده قابل پیش بینی است، اما مدل داده های مربوط به حمله -ix-داده شامل بهبود کیفیت زندگی یافت نمی شود در MITRE /CTI.
لطفاً ببینید که [KEEP_0] برای اطلاعات بیشتر در مورد مدل داده های بهبود یافته آن مخزن.

#localization فارسی

این مدل شامل یک ابزار ترجمه برای تولید فارسی ([KEEP_0] نسخه ای از مجموعه داده های CTI است:

[[ویرایش]

ویژگی های کلیدی:

ترجمه و ترجمه ی قرآن کریم (قرآن)
شناسه ها، URL ها، کدهای ATT & CK و نشانه های استنادی دست نخورده
- استفاده از یک حافظه پایدار SQLite برای بازسازی سریع تر
خروجی را به یک دایرکتوری جداگانه به طور پیش فرض (ایمنی، غیر مخرب) بنویسید.

شروع سریع:

```bash
# 1) smoke test on a small sample
python3 scripts/translate_cti_to_persian.py --dry-run --limit 50

# 2) full translation into translated/fa/
python3 scripts/translate_cti_to_persian.py
```

حالت کاملا رایگان آفلاین (برای اجراهای بزرگ باز می شود):

```bash
# one-time install
pip install argostranslate

# first run downloads en->fa model package once, then translates locally
python3 scripts/translate_cti_to_persian.py --provider argos_offline

# resume an interrupted run without rewriting translated files
python3 scripts/translate_cti_to_persian.py --provider argos_offline --skip-existing
```

در کنار کلید های اصلی در فایل های اصلی JSON ([KEEP_0]) بنویسید.
[[ویرایش]

```bash
python3 scripts/translate_cti_to_persian.py \
  --provider argos_offline \
  --mode suffix \
  --in-place \
  --skip-existing \
  --workers 16
```

اگر پایتون 3.9 است، استفاده کنید:

```bash
pip install "argostranslate==1.9.6"
```

اختیاری: استفاده از مقام رسمی Google Cloud Translation API:

```bash
export GOOGLE_TRANSLATE_API_KEY="your_api_key"
python3 scripts/translate_cti_to_persian.py --provider google_cloud
```

اگر پایتون محلی شما نمی تواند گواهینامه های TLS را تأیید کند، یک بسته CA را به صراحت منتقل کنید:

```bash
python3 scripts/translate_cti_to_persian.py --ca-bundle /path/to/cacert.pem
```

پرچم های مفید:

[KEEP_0] (default): متن فارسی را به نسخه های ترجمه شده می نویسد
[KEEP_0]: نگه داشتن متن اصلی و ذخیره رشته های فارسی در [KEEP] به عنوان مسیر / منبع / ورودی ترجمه
[[رده:رده: [[رده:]] و [[رده:]]
[KEEP_0]: به طور مستقیم به فایل های JSON منبع بنویسید
[KEEP_0] : محدود کردن داده های سطح بالا برای پردازش
[KEEP_0] : پردازش اولین فایل های N
[KEEP_0] : ترجمه شده در مسیر JSON
[KEEP_0]: ترجمه کامل محلی پس از نصب مدل
[[ویرایش] مدل Argos download/install
[KEEP_0]: مدل واردات از فایل محلی
[[رده:رده: [[رده:]]
[KEEP_0]: استفاده از ترجمه های موجود از ارائه دهنده دیگر

نکات عملکرد:

افزایش ([ویرایش] (به عنوان مثال [KEEP] یا [KEEP_2]) و تست در ابتدا [KEEP_3].
استفاده از آن به سرعت آغاز می شود.
- برای مهلت، مجموعه داده ها را به طور موازی در ترمینال های جداگانه با حافظه های جداگانه اجرا کنید:

```bash
# Terminal 1
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets enterprise-attack --cache-db .translation-cache/ent.sqlite3 --workers 16

# Terminal 2
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets mobile-attack ics-attack --cache-db .translation-cache/mob_ics.sqlite3 --workers 16

# Terminal 3
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets pre-attack capec --cache-db .translation-cache/pre_capec.sqlite3 --workers 16
```

# ATT & CK

MITRE ATT & CK یک پایه دانش در سطح جهانی از تاکتیک های دشمن و تکنیک های مبتنی بر مشاهدات دنیای واقعی است.
پایگاه دانش ATT & CK به عنوان پایه ای برای توسعه مدل های تهدید خاص و روش در بخش خصوصی، در دولت و در جامعه محصول و خدمات امنیت سایبری استفاده می شود.

↑ [[ویرایش]

# CAPEC

درک اینکه چگونه دشمن عمل می کند برای امنیت سایبری موثر است.
CAPECTM با ارائه یک فرهنگ لغت جامع از الگوهای شناخته شده توسط دشمنان برای بهره برداری از ضعف های شناخته شده در قابلیت های فعال سایبری کمک می کند.
این می تواند توسط تحلیلگران، توسعه دهندگان، تسترها و مربیان برای پیشبرد درک جامعه و افزایش دفاع استفاده شود.

تمرکز بر امنیت برنامه
- بهره برداری در برابر سیستم های آسیب پذیر
شامل مهندسی اجتماعی / زنجیره تامین
مرتبط با تزریق مشترک (CMA)

↑ [[ویرایش]

# STIX

بیان اطلاعات تهدید ساختاری (STIXTM) یک فرمت زبان و سریال سازی است که برای تبادل اطلاعات تهدید سایبری (CTI) استفاده می شود.

STIX سازمان ها را قادر می سازد تا CTI را با یکدیگر به شیوه ای سازگار و قابل خواندن به اشتراک بگذارند، به جوامع امنیتی اجازه می دهد تا بهتر شوند.
درک کنید که چه حملات مبتنی بر کامپیوتر به احتمال زیاد دیده می شوند و یا سریعتر و موثرتر به این حملات پاسخ می دهند.

STIX برای بهبود بسیاری از قابلیت های مختلف، مانند تجزیه و تحلیل تهدید مشترک، تبادل تهدید خودکار، تشخیص خودکار و پاسخ، و بیشتر طراحی شده است.

↑ [[ویرایش]
