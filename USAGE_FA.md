# مقدمه

[[ویرایش]
>> ** اطلاع رسانی
>>
>> ما STDX 2.0 و STIX 2.1 را به یک مشخصات واحد متصل کرده ایم.
>> برای اکثر اطلاعات به روز در مورد ساختار و فرمت فایل های منتشر شده STIX،
و ببینید که چه می شود.
>>
>> این سند بر نمونه های کاربردی و دستورالعمل های پایتون برای کار با داده های ATT & CK تمرکز دارد. برای اطلاعات دقیق در مورد انواع شی، زمینه ها و روابط، لطفا به مشخصات مرتبط با بالا اشاره کنید.

این سند توضیح می دهد که چگونه داده های ATT & CK را از هر دو مخزن یا سرور ATT&CK TAXII با استفاده از پایتون جستجو و دستکاری کنید.

استفاده از ATT & CK نشان داده شده در این سند از [KEEP_0] استفاده می کند. لطفا به [[KEEP] مراجعه کنید تا اطلاعات بیشتری در مورد چگونگی کار با برنامه نویسی STIX داشته باشید.

ما همچنین توصیه می کنیم که کتاب را بخوانید.

اگر به دنبال داده های ATT&CK هستید که در STIX 2.1 نشان داده شده است، لطفاً (KEEP_0) را ببینید. مخزن GitHub

# جدول محتوای

[[ویرایش]
  [[ویرایش]
  [[ویرایش]
  [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
    [[ویرایش]
  [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
      [[ویرایش]
        [[ویرایش]
        [[ویرایش]
      [[ویرایش]
      [[ویرایش]
      [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]
    [[ویرایش]
      [[ویرایش]
      [[ویرایش]

# ATT & CK Object Type

ATT & CK از ترکیبی از اشیاء از پیش تعریف شده و سفارشی STIX برای پیاده سازی مفاهیم ATT & CK استفاده می کند. برای یک ویژگی کامل از انواع اشیاء ATT & CK، زمینه ها و روابط آنها، لطفا به [KEEP_0] مراجعه کنید.

### دسترسی به داده های ATT & CK در python

چندین راه برای به دست آوردن اطلاعات ATT & CK در پایتون وجود دارد. همه آنها یک شی را ارائه می دهند
استفاده از DataStore API و می تواند به جای دستورالعمل های ارائه شده در بخش [KEEP_0] استفاده شود.

این بخش از آن استفاده می کند. لطفا به [[KEEP] مراجعه کنید تا اطلاعات بیشتری در مورد چگونگی کار با برنامه نویسی STIX داشته باشید.

## الزامات و واردات

قبل از نصب الزامات، توصیه می کنیم یک محیط مجازی ایجاد کنید:

1. ایجاد محیط مجازی:
    macOS and Linux:[KEEP_0]
    ویندوز: [KEEP_0]
2. محیط مجازی را فعال کنید:
    macOS and Linux:[KEEP_0]
    ویندوز: [KEEP_0]

####

[[ویرایش] واردات برای دستورالعمل های موجود در این مخزن را می توان از بسته پایه به عنوان مثال:

```python
from stix2 import Filter
```

با این حال، اگر قصد دارید مجموعه داده های ATT & CK را با اشیاء جدید گسترش دهید یا جریان های کاری پیچیده را پیاده سازی کنید، ممکن است لازم باشد از [KEEP_0] برای برخی از واردات استفاده کنید. این تضمین می کند که اشیاء به جای سیستم STIX 2.0 از API استفاده می کنند. برای مثال:

```python
from stix2.v20 import AttackPattern
```

شما می توانید یک لیست کامل از کلاس ها را ببینید که دارای واردات است.

# تاکسی #iclient

[[ویرایش] سرور ATT & CK TAXII نسخه 2.0 از مشخصات TAXII را پیاده سازی می کند، اما واردات پیش فرض [KEEP_0] (نسخه 2.0.0 و بالاتر) می تواند منجر به 406 پاسخ در هنگام اتصال به سرور TAXII ما شود.

اگر مشتری TAXII به 406 پاسخ می دهد، مطمئن شوید که آخرین نسخه را اجرا می کنید. علاوه بر این، مطمئن شوید که نسخه 2.0 مشتری را اجرا می کنید (با استفاده از [KEEP_2] واردات - همانطور که در زیر نشان داده شده است برای ارتباط با ATT & CK TAXII 2.0 Server.

```python
from taxii2client.v20 import Collection
```

#### دسترسی به محتوای محلی

بسیاری از کاربران ممکن است از طریق یک کپی محلی از داده های STIX در این repo به محتوای ATT & CK دسترسی داشته باشند. این می تواند به چند دلیل سودمند باشد:

• نیاز به دسترسی به اینترنت پس از دانلود اولیه
کاربر می تواند محتوای ATT & CK را در صورت تمایل تغییر دهد
- کپی های دانلود شده استاتیک است، بنابراین به روز رسانی به کاتالوگ ATT & CK باعث ایجاد اشکالات در جریان کار خودکار نمی شود. کاربر هنوز هم می تواند به صورت دستی با جمع آوری یک نسخه جدید از داده ها به روز رسانی کند.

## دسترسی از طریق FilesystemSource

هر کدام از این موارد به صورت رسمی در دسترس هستند.
پس شما می توانید از یک [KEEP_0] برای بارگذاری یک دامنه استفاده کنید، برای مثال دامنه حمله شرکت:

```python
from stix2 import FileSystemSource

src = FileSystemSource('./cti/enterprise-attack')
```

##### دسترسی از طریق بسته

اگر شما ترجیح می دهید فقط بسته دامنه را دانلود کنید، به عنوان مثال [KEEP_0]، شما هنوز هم می توانید این را با استفاده از MemoryStore بارگیری کنید:

```python
from stix2 import MemoryStore

src = MemoryStore()
src.load_from_file("enterprise-attack.json")
```

#### دسترسی به محتوای زنده

برخی از کاربران ممکن است ترجیح دهند به محتوای ATT & CK در اینترنت دسترسی پیدا کنند. این به چند دلیل سودمند است:

همیشه با کاتالوگ ATT & CK در حال تحول باقی می ماند
نیازی به دانلود اولیه محتوای ATT & CK نیست، به طور کلی نیاز به تنظیمات کمتری دارد.

## دسترسی از سرور ATT & CK TAXII

کاربران می توانند به داده های ATT & CK از سرور رسمی ATT & CK TAXII دسترسی داشته باشند. در TAXII، دامنه های ATT & CK به عنوان مجموعه ای با شناسه های استاتیک نشان داده می شوند:

دامنه | Collection ID |
| | |
[[ویرایش] | |
[[ویرایش] | |
[[ویرایش] | |

شما همچنین می توانید لیستی از جمع آوری های موجود را مستقیما از سرور دریافت کنید:

```python
from taxii2client.v20 import Server # only specify v20 if your installed version is >= 2.0.0

server = Server("https://cti-taxii.mitre.org/taxii/")
api_root = server.api_roots[0]
# Print name and ID of all ATT&CK domains available as collections
for collection in api_root.collections:
    print(collection.title.ljust(20) + collection.id)
```

دستورالعمل زیر نشان می دهد که چگونه به داده های حمله شرکت از سرور TAXII دسترسی پیدا کنید.

```python
from stix2 import TAXIICollectionSource
from taxii2client.v20 import Collection # only specify v20 if your installed version is >= 2.0.0

collections = {
    "enterprise_attack": "95ecc380-afe9-11e4-9b6c-751b66dd541e",
    "mobile_attack": "2f669986-b40b-4423-b720-4396ca6a462b",
    "ics-attack": "02c3ef24-9cd4-48f3-a99f-b74ce24f1d34"
}

collection = Collection(f"https://cti-taxii.mitre.org/stix/collections/{collections['enterprise_attack']}/")
src = TAXIICollectionSource(collection)
```

برای بیشتر در مورد TAXII، لطفا نگاهی به oasis-open بیاندازید.

## دسترسی از Github از طریق درخواست

کاربران می توانند به طور جایگزین به داده های MITRE/CTI با استفاده از درخواست های HTTP دسترسی پیدا کنند و محتوای حاصل را به یک MemoryStore بارگذاری کنند.
در حالی که به طور معمول روش TAXII برای دسترسی به "زنده" مطلوب تر است، این روش می تواند مفید باشد اگر شما می خواهید به
دسترسی به داده ها در یک شاخه از MITRE/CTI repo ( سرور TAXII فقط شاخه کارشناسی ارشد را نگه می دارد) یا در مورد قطع سرور TAXII.

```python
import requests
from stix2 import MemoryStore

def get_data_from_branch(domain, branch="master"):
    """get the ATT&CK STIX data from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'. Branch should typically be master."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/{branch}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_branch("enterprise-attack")
```

#### دسترسی به یک نسخه خاص از ATT & CK

نسخه های ATT & CK در MITRE/CTI با استفاده از [KEEP_2] ردیابی می شوند. برچسب ها با استفاده از نسخه های ATT&CK و تگ های پیشوند ([KEEP] با نسخه های CAPEC مطابقت دارند. شما می توانید اطلاعات بیشتری در مورد نسخه های ATT & CK در وب سایت ATT & CK پیدا کنید.

علاوه بر چک کردن repo در زیر برچسب برای یک نسخه داده شده یا دانلود STIX از github با استفاده از مرورگر خود، شما همچنین می توانید از تغییرات در [KEEP_0] برای دسترسی به یک نسخه خاص از ATT & CK استفاده کنید:

```python
import requests
from stix2 import MemoryStore

def get_data_from_version(domain, version):
    """get the ATT&CK STIX data for the given version from MITRE/CTI. Domain should be 'enterprise-attack', 'mobile-attack' or 'ics-attack'."""
    stix_json = requests.get(f"https://raw.githubusercontent.com/mitre/cti/ATT%26CK-v{version}/{domain}/{domain}.json").json()
    return MemoryStore(stix_data=stix_json["objects"])

src = get_data_from_version("enterprise-attack", "5.2")
```

شما می توانید لیستی از نسخه های ATT & CK را که به صورت موضوعی با استفاده از github API برنامه ریزی شده اند، دریافت کنید:

```python
import requests
import re

refToTag = re.compile(r"ATT&CK-v(.*)")
tags = requests.get("https://api.github.com/repos/mitre/cti/git/refs/tags").json()
versions = list(map(lambda tag: refToTag.search(tag["ref"]).groups()[0] , filter(lambda tag: "ATT&CK-v" in tag["ref"], tags)))
# versions = ["1.0", "2.0", ...]
```

#### دسترسی به چندین دامنه همزمان

از آنجا که ATT & CK در دامنه های مختلف ذخیره می شود (مانند این نوشتار، حمله شرکت، حمله تلفن همراه و حمله)، روش های فوق تنها به شما اجازه می دهد تا کار کنید.
با یک دامنه واحد در یک زمان در حالی که اغلب اوقات جداسازی سخت دامنه ها سودمند است، گاهی اوقات ترکیب آن مفید است.
دامنه ها در یک DataStore واحد از هر یک از روش های فوق برای به دست آوردن داده های فردی استفاده کنید و سپس از روش زیر برای ترکیب آنها در ترکیب آنها استفاده کنید.
یک منبع کامپوزیت:

```python
from stix2 import CompositeDataSource

src = CompositeDataSource()
src.add_data_sources([enterprise_attack_src, mobile_attack_src, ics_attack_src])
```

سپس شما می توانید از این کامپوزیت منبع استفاده کنید، همانطور که شما می توانید DataSource را برای یک دامنه فردی استفاده کنید.

## دستور العمل های پایتون

در زیر دستورالعمل های python وجود دارد که می تواند برای کار با داده های ATT & CK استفاده شود. آنها فرض می کنند که وجود یک شی در اجرای API DataStore وجود دارد. هر یک از روش های ذکر شده در بخش [KEEP_0] باید یک شی را برای اجرای این API ارائه دهد.

این بخش از آن استفاده می کند. لطفا به [[KEEP] مراجعه کنید تا اطلاعات بیشتری در مورد چگونگی کار با برنامه نویسی STIX داشته باشید. همچنین بخوانید :

#### گرفتن یک شی

دستورالعمل ها در این بخش به چگونگی جستجوی مجموعه داده ها برای یک شی واحد می پردازد.

##### توسط STIX ID

دستورالعمل زیر می تواند برای بازیابی یک شی با توجه به شناسه STDX استفاده شود. این به طور معمول راه ترجیحی برای بازیابی اشیاء در هنگام کار با داده های ATT & CK است، زیرا شناسه های STIX تضمین شده است منحصر به فرد است.

```python
g0075 = src.get("intrusion-set--f40eb8ce-2a74-4e56-89a1-227021410142")
```

##### ATT & CK ID

دستورالعمل زیر می تواند برای بازیابی یک شی با توجه به ATT & CK ID استفاده شود:

```python
from stix2 import Filter

g0075 = src.query([ Filter("external_references.external_id", "=", "G0075") ])[0]
```

توجه: در نسخه های قبلی ATT & CK، کاهش 1 رابطه با تکنیک ها و شناسه تکنیک خود را به اشتراک گذاشت. بنابراین روش فوق به درستی برای تکنیک ها کار نمی کند، زیرا تکنیک ATT & CK ID ها واقعا منحصر به فرد نیستند. با مشخص کردن نوع STIX شما به دنبال آن هستید. می توانید از این مسئله اجتناب کنید.

```python
from stix2 import Filter

t1134 = src.query([ 
    Filter("external_references.external_id", "=", "T1134"), 
    Filter("type", "=", "attack-pattern")
])[0]
```

در حالی که در آن زمان، این مسئله را از بین می برد، شما می توانید آن ها را به این ترتیب فیلتر کنید.

##### با نام

دستورالعمل زیر یک شی را با توجه به نام آن بازیابی می کند:

```python
from stix2 import Filter

def get_technique_by_name(thesrc, name):
    filt = [
        Filter('type', '=', 'attack-pattern'),
        Filter('name', '=', name)
    ]
    return thesrc.query(filt)
# get the technique titled "System Information Discovery"
get_technique_by_name(src, 'System Information Discovery')
```

##### سوگند به سوگند

روش زیر را می توان برای پیدا کردن گروه مربوط به alias داده شده استفاده کرد:

```python
from stix2 import Filter

def get_group_by_alias(thesrc, alias):
    return thesrc.query([
        Filter('type', '=', 'intrusion-set'),
        Filter('aliases', '=', alias)
    ])[0]
    
get_group_by_alias(src, 'Cozy Bear')
```

#### دریافت چندین شیء

دستورالعمل ها در این بخش به چگونگی جستجوی مجموعه داده ها برای اشیاء متعدد می پردازد.

و #9888: هنگام کار با پرس و جو برای بازگرداندن اشیاء بر اساس مجموعه ای از ویژگی ها، احتمال دارد که شما با چند شی که دیگر توسط ATT & CK حفظ نمی شود، پایان دهید. این ها اشیایی هستند که به عنوان تخریب شده یا لغو می شوند. ما این اشیاء قدیمی را در اطراف نگه می داریم تا جریان های کاری بسته به آنها شکسته نشوند، اما توصیه می کنیم که از استفاده از آنها در صورت امکان اجتناب کنید. لطفا بخش [KEEP_0] را برای اطلاعات بیشتر ببینید.

##### اشیاء از نوع

[KEEP_0] را برای نقشه برداری از نوع ATT&CK به نوع STIX ببینید.

```python
from stix2 import Filter

# use the appropriate STIX type in the query according to the desired ATT&CK type
groups = src.query([ Filter("type", "=", "intrusion-set") ])
```

###### تکنیک ها یا زیر تکنولوژی ها

ATT & CK تکنیک ها و زیر تکنولوژی ها هر دو به عنوان اشیاء [KEEP_0] نمایندگی می شوند. بنابراین تجزیه و تحلیل بیشتر برای به دست آوردن تکنیک های خاص یا زیر تکنولوژی های ضروری است.

```python
from stix2 import Filter

def get_techniques_or_subtechniques(thesrc, include="both"):
    """Filter Techniques or Sub-Techniques from ATT&CK Enterprise Domain.
    include argument has three options: "techniques", "subtechniques", or "both"
    depending on the intended behavior."""
    if include == "techniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', False)
        ])
    elif include == "subtechniques":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern'),
            Filter('x_mitre_is_subtechnique', '=', True)
        ])
    elif include == "both":
        query_results = thesrc.query([
            Filter('type', '=', 'attack-pattern')
        ])
    else:
        raise RuntimeError("Unknown option %s!" % include)

    return query_results


subtechniques = get_techniques_or_subtechniques(src, "subtechniques")
subtechniques = remove_revoked_deprecated(subtechniques) # see https://github.com/mitre/cti/blob/master/USAGE.md#removing-revoked-and-deprecated-objects
```

###### دریافت نرم افزار

از آنجا که نرم افزار دو نوع STIX است ([KEEP_0] و [KEEP])) ، روند دسترسی به نرم افزار کمی پیچیده تر است.

```python
from itertools import chain
from stix2 import Filter

def get_software(thesrc):
    return list(chain.from_iterable(
        thesrc.query(f) for f in [
            Filter("type", "=", "tool"), 
            Filter("type", "=", "malware")
        ]
    ))

get_software(src)
```

##### اشیاء توسط محتوا

گاهی اوقات ممکن است مفید باشد که اشیاء را با محتوای شرح آنها جستجو کنید:

```python
from stix2 import Filter

def get_techniques_by_content(thesrc, content):
    techniques = src.query([ Filter('type', '=', 'attack-pattern') ])
    return list(filter(lambda t: content.lower() in t.description.lower(), techniques))

# Get all techniques where the string LSASS appears in the description
get_techniques_by_content(src, 'LSASS')
```

##### تکنیک های پلتفرم

تکنیک ها با یک یا چند سیستم عامل مرتبط هستند. شما می توانید تکنیک ها را جستجو کنید
زیر یک پلت فرم خاص با کد زیر:

```python
from stix2 import Filter

def get_techniques_by_platform(thesrc, platform):
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('x_mitre_platforms', '=', platform)
    ])

# get techniques in the windows platform
get_techniques_by_platform(src, 'Windows')
```

##### تکنیک های تاکتیک

تکنیک ها مربوط به تاکتیک ها توسط مالکیت Kill_chain_systems هستند.
و هر یک از آنها را از هر یک از اجزای آن جدا می کند.

```python
from stix2 import Filter

def get_tactic_techniques(thesrc, tactic):
    # double checking the kill chain is MITRE ATT&CK
    # note: kill_chain_name is different for other domains:
    #    - enterprise: "mitre-attack"
    #    - mobile: "mitre-mobile-attack"
    #    - ics: "mitre-ics-attack"
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('kill_chain_phases.phase_name', '=', tactic),
        Filter('kill_chain_phases.kill_chain_name', '=', 'mitre-attack'),
    ])


# use the x_mitre_shortname as argument
get_tactic_techniques(src, 'defense-evasion')
```

# # # # Tactics by ماتریس

این تاکتیک ها اشیاء فردی هستند ([KEEP_0] و سفارش آنها در ماتریس ([[KEEP]) است.
در داخل آن قرار دارد. سفارش تاکتیک ها در این لیست مطابقت دارد
سفارش تاکتیک ها در این ماتریس دستورالعمل زیر یک لیست ساختاری از تاکتیک ها را در هر ماتریس DataStore ورودی باز می گرداند.

```python
from stix2 import Filter

def getTacticsByMatrix(thesrc):
    tactics = {}
    matrix = thesrc.query([
        Filter('type', '=', 'x-mitre-matrix'),
    ])
    
    for i in range(len(matrix)):
        tactics[matrix[i]['name']] = []
        for tactic_id in matrix[i]['tactic_refs']:
            tactics[matrix[i]['name']].append(thesrc.get(tactic_id))
    
    return tactics

# get tactic layout
getTacticsByMatrix(src)
```

##### اشیاء ایجاد شده یا اصلاح شده از زمان تاریخ معین

گاهی اوقات ممکن است بخواهید فهرستی از اشیایی را که بعد از یک زمان مشخص ایجاد یا اصلاح شده اند، تهیه کنید.

```python
from stix2 import Filter

def get_created_after(thesrc, timestamp):
    filt = [
        Filter('created', '>', timestamp)
    ]
    return thesrc.query(filt)

get_created_after(src, "2018-10-01T00:14:20.652Z")


def get_modified_after(thesrc, timestamp):
    filt = [
        Filter('modified', '>', timestamp)
    ]
    return thesrc.query(filt)
    
get_modified_after(src, "2018-10-01T00:14:20.652Z")
```

ما توصیه نمی کنیم که از این روش برای تشخیص تغییر در محتویات پایه دانش استفاده کنید. برای تشخیص به روز رسانی به پایگاه دانش کلی ما توصیه می کنیم از درخواست برای استفاده از [KEEP_0] استفاده کنید.

#### دریافت اشیاء مرتبط

بخش بزرگی از کار با ATT & CK حول و حوش روابط بین اشیاء می چرخد. مفید است
نه تنها موضوع مرتبط بلکه خود رابطه را پیگیری می کند، زیرا یک توصیف اغلب به این دلیل است.
حال برای بیان ماهیت رابطه دستورالعمل های زیر نشان می دهند
برخی از کاربردهای مشترک روابط

## روابط کوچک

نکته: در نظر گرفته شده است که کد زیر با انتشار ATT&CK v12 که شامل اشیاء کمپین است، استفاده شود.
نمونه ها برای نسخه های قبلی ATT و CK که این اشیاء را حذف می کنند، سازگار هستند.

این تعادل کوچک را می توان برای ساخت یک جدول نگاه از stixID به اشیاء و روابط مرتبط استفاده کرد.
بحث در مورد هر تابع Accessor یک MemoryStore STDX2 برای ساخت نقشه های ارتباطی است.

```python
from pprint import pprint
from stix2 import MemoryStore, Filter

# See section below on "Removing revoked and deprecated objects"
def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

def get_related(thesrc, src_type, rel_type, target_type, reverse=False):
    """build relationship mappings
       params:
         thesrc: MemoryStore to build relationship lookups for
         src_type: source type for the relationships, e.g "attack-pattern"
         rel_type: relationship type for the relationships, e.g "uses"
         target_type: target type for the relationship, e.g "intrusion-set"
         reverse: build reverse mapping of target to source
    """

    relationships = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', rel_type),
        Filter('revoked', '=', False),
    ])

    # See section below on "Removing revoked and deprecated objects"
    relationships = remove_revoked_deprecated(relationships)

    # stix_id => [ { relationship, related_object_id } for each related object ]
    id_to_related = {}

    # build the dict
    for relationship in relationships:
        if src_type in relationship.source_ref and target_type in relationship.target_ref:
            if (relationship.source_ref in id_to_related and not reverse) or (relationship.target_ref in id_to_related and reverse):
                # append to existing entry
                if not reverse:
                    id_to_related[relationship.source_ref].append({
                        "relationship": relationship,
                        "id": relationship.target_ref
                    })
                else:
                    id_to_related[relationship.target_ref].append({
                        "relationship": relationship,
                        "id": relationship.source_ref
                    })
            else:
                # create a new entry
                if not reverse:
                    id_to_related[relationship.source_ref] = [{
                        "relationship": relationship,
                        "id": relationship.target_ref
                    }]
                else:
                    id_to_related[relationship.target_ref] = [{
                        "relationship": relationship,
                        "id": relationship.source_ref
                    }]
    # all objects of relevant type
    if not reverse:
        targets = thesrc.query([
            Filter('type', '=', target_type),
            Filter('revoked', '=', False)
        ])
    else:
        targets = thesrc.query([
            Filter('type', '=', src_type),
            Filter('revoked', '=', False)
        ])

    # build lookup of stixID to stix object
    id_to_target = {}
    for target in targets:
        id_to_target[target.id] = target

    # build final output mappings
    output = {}
    for stix_id in id_to_related:
        value = []
        for related in id_to_related[stix_id]:
            if not related["id"] in id_to_target:
                continue  # targeting a revoked object
            value.append({
                "object": id_to_target[related["id"]],
                "relationship": related["relationship"]
            })
        output[stix_id] = value
    return output

# software:group
def software_used_by_groups(thesrc):
    """returns group_id => {software, relationship} for each software used by the group and each software used by campaigns attributed to the group."""
    # get all software used by groups
    tools_used_by_group = get_related(thesrc, "intrusion-set", "uses", "tool")
    malware_used_by_group = get_related(thesrc, "intrusion-set", "uses", "malware")
    software_used_by_group = {**tools_used_by_group, **malware_used_by_group} # group_id -> [{software, relationship}]

    # get groups attributing to campaigns and all software used by campaigns
    software_used_by_campaign = get_related(thesrc, "campaign", "uses", "tool")
    malware_used_by_campaign = get_related(thesrc, "campaign", "uses", "malware")
    for id in malware_used_by_campaign:
        if id in software_used_by_campaign:
            software_used_by_campaign[id].extend(malware_used_by_campaign[id])
        else:
            software_used_by_campaign[id] = malware_used_by_campaign[id]
    campaigns_attributed_to_group = {
        "campaigns": get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
        "software": software_used_by_campaign # campaign_id => {software, relationship}
    }

    for group_id in campaigns_attributed_to_group["campaigns"]:
        software_used_by_campaigns = []
        # check if attributed campaign is using software
        for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in campaigns_attributed_to_group["software"]:
                software_used_by_campaigns.extend(campaigns_attributed_to_group["software"][campaign_id])
        
        # update software used by group to include software used by a groups attributed campaign
        if group_id in software_used_by_group:
            software_used_by_group[group_id].extend(software_used_by_campaigns)
        else:
            software_used_by_group[group_id] = software_used_by_campaigns
    return software_used_by_group

def groups_using_software(thesrc):
    """returns software_id => {group, relationship} for each group using the software and each software used by attributed campaigns."""
    # get all groups using software
    groups_using_tool = get_related(thesrc, "intrusion-set", "uses", "tool", reverse=True)
    groups_using_malware = get_related(thesrc, "intrusion-set", "uses", "malware", reverse=True)
    groups_using_software = {**groups_using_tool, **groups_using_malware} # software_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using software
    campaigns_using_software = get_related(thesrc, "campaign", "uses", "tool", reverse=True)
    campaigns_using_malware = get_related(thesrc, "campaign", "uses", "malware", reverse=True)
    for id in campaigns_using_malware:
        if id in campaigns_using_software:
            campaigns_using_software[id].extend(campaigns_using_malware[id])
        else:
            campaigns_using_software[id] = campaigns_using_malware[id]
    groups_attributing_to_campaigns = {
        "campaigns": campaigns_using_software,# software_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for software_id in groups_attributing_to_campaigns["campaigns"]:
        groups_attributed_to_campaigns = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][software_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                groups_attributed_to_campaigns.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using software to include software used by a groups attributed campaign
        if software_id in groups_using_software:
            groups_using_software[software_id].extend(groups_attributed_to_campaigns)
        else:
            groups_using_software[software_id] = groups_attributed_to_campaigns
    return groups_using_software

# software:campaign
def software_used_by_campaigns(thesrc):
    """returns campaign_id => {software, relationship} for each software used by the campaign."""
    tools_used_by_campaign = get_related(thesrc, "campaign", "uses", "tool")
    malware_used_by_campaign = get_related(thesrc, "campaign", "uses", "malware")
    return {**tools_used_by_campaign, **malware_used_by_campaign}

def campaigns_using_software(thesrc):
    """returns software_id => {campaign, relationship} for each campaign using the software."""
    campaigns_using_tool = get_related(thesrc, "campaign", "uses", "tool", reverse=True)
    campaigns_using_malware = get_related(thesrc, "campaign", "uses", "malware", reverse=True)
    return {**campaigns_using_tool, **campaigns_using_malware}

# campaign:group
def groups_attributing_to_campaign(thesrc):
    """returns campaign_id => {group, relationship} for each group attributing to the campaign."""
    return get_related(thesrc, "campaign", "attributed-to", "intrusion-set")

def campaigns_attributed_to_group(thesrc):
    """returns group_id => {campaign, relationship} for each campaign attributed to the group."""
    return get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True)

# technique:group
def techniques_used_by_groups(thesrc):
    """returns group_id => {technique, relationship} for each technique used by the group and each
       technique used by campaigns attributed to the group."""
    # get all techniques used by groups
    techniques_used_by_groups = get_related(thesrc, "intrusion-set", "uses", "attack-pattern") # group_id => {technique, relationship}

    # get groups attributing to campaigns and all techniques used by campaigns
    campaigns_attributed_to_group = {
        "campaigns": get_related(thesrc, "campaign", "attributed-to", "intrusion-set", reverse=True), # group_id => {campaign, relationship}
        "techniques": get_related(thesrc, "campaign", "uses", "attack-pattern") # campaign_id => {technique, relationship}
    }

    for group_id in campaigns_attributed_to_group["campaigns"]:
        techniques_used_by_campaigns = []
        # check if attributed campaign is using technique
        for campaign in campaigns_attributed_to_group["campaigns"][group_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in campaigns_attributed_to_group["techniques"]:
                techniques_used_by_campaigns.extend(campaigns_attributed_to_group["techniques"][campaign_id])

        # update techniques used by groups to include techniques used by a groups attributed campaign
        if group_id in techniques_used_by_groups:
            techniques_used_by_groups[group_id].extend(techniques_used_by_campaigns)
        else:
            techniques_used_by_groups[group_id] = techniques_used_by_campaigns
    return techniques_used_by_groups

def groups_using_technique(thesrc):
    """returns technique_id => {group, relationship} for each group using the technique and each campaign attributed to groups using the technique."""
    # get all groups using techniques
    groups_using_techniques = get_related(thesrc, "intrusion-set", "uses", "attack-pattern", reverse=True) # technique_id => {group, relationship}

    # get campaigns attributed to groups and all campaigns using techniques
    groups_attributing_to_campaigns = {
        "campaigns": get_related(thesrc, "campaign", "uses", "attack-pattern", reverse=True), # technique_id => {campaign, relationship}
        "groups": get_related(thesrc, "campaign", "attributed-to", "intrusion-set") # campaign_id => {group, relationship}
    }

    for technique_id in groups_attributing_to_campaigns["campaigns"]:
        campaigns_attributed_to_group = []
        # check if campaign is attributed to group
        for campaign in groups_attributing_to_campaigns["campaigns"][technique_id]:
            campaign_id = campaign["object"]["id"]
            if campaign_id in groups_attributing_to_campaigns["groups"]:
                campaigns_attributed_to_group.extend(groups_attributing_to_campaigns["groups"][campaign_id])
        
        # update groups using techniques to include techniques used by a groups attributed campaign
        if technique_id in groups_using_techniques:
            groups_using_techniques[technique_id].extend(campaigns_attributed_to_group)
        else:
            groups_using_techniques[technique_id] = campaigns_attributed_to_group
    return groups_using_techniques

# technique:campaign
def techniques_used_by_campaigns(thesrc):
    """returns campaign_id => {technique, relationship} for each technique used by the campaign."""
    return get_related(thesrc, "campaign", "uses", "attack-pattern")

def campaigns_using_technique(thesrc):
    """returns technique_id => {campaign, relationship} for each campaign using the technique."""
    return get_related(thesrc, "campaign", "uses", "attack-pattern", reverse=True)

# technique:software
def techniques_used_by_software(thesrc):
    """return software_id => {technique, relationship} for each technique used by the software."""
    techniques_by_tool = get_related(thesrc, "tool", "uses", "attack-pattern")
    techniques_by_malware = get_related(thesrc, "malware", "uses", "attack-pattern")
    return {**techniques_by_tool, **techniques_by_malware}

def software_using_technique(thesrc):
    """return technique_id  => {software, relationship} for each software using the technique."""
    tools_by_technique_id = get_related(thesrc, "tool", "uses", "attack-pattern", reverse=True)
    malware_by_technique_id = get_related(thesrc, "malware", "uses", "attack-pattern", reverse=True)
    return {**tools_by_technique_id, **malware_by_technique_id}

# technique:mitigation
def mitigation_mitigates_techniques(thesrc):
    """return mitigation_id => {technique, relationship} for each technique mitigated by the mitigation."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=False)

def technique_mitigated_by_mitigations(thesrc):
    """return technique_id => {mitigation, relationship} for each mitigation of the technique."""
    return get_related(thesrc, "course-of-action", "mitigates", "attack-pattern", reverse=True)

# technique:sub-technique
def subtechniques_of(thesrc):
    """return technique_id => {subtechnique, relationship} for each subtechnique of the technique."""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern", reverse=True)

def parent_technique_of(thesrc):
    """return subtechnique_id => {technique, relationship} describing the parent technique of the subtechnique"""
    return get_related(thesrc, "attack-pattern", "subtechnique-of", "attack-pattern")[0]

# technique:data-component
def datacomponent_detects_techniques(thesrc):
    """return datacomponent_id => {technique, relationship} describing the detections of each data component"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern")

def technique_detected_by_datacomponents(thesrc):
    """return technique_id => {datacomponent, relationship} describing the data components that can detect the technique"""
    return get_related(thesrc, "x-mitre-data-component", "detects", "attack-pattern", reverse=True)

# Example usage:
src = MemoryStore()
src.load_from_file("path/to/enterprise-attack.json")

group_id_to_software = software_used_by_groups(src)
pprint(group_id_to_software["intrusion-set--2a158b0a-7ef8-43cb-9985-bf34d1e12050"])  # G0019
# [
#     {
#         "object": Malware, # S0061
#         "relationship": Relationship # relationship between G0019 and S0061
#     },
#     {
#         ...
#     }
# ]
```

##### تکنیک های استفاده شده توسط نرم افزار گروهی

از آنجا که یک گروه از نرم افزار استفاده می کند و نرم افزار از تکنیک ها استفاده می کند، گروه ها می توانند کاربران غیرمستقیم تکنیک های استفاده شده توسط نرم افزار خود را در نظر بگیرند.
این تکنیک ها اغلب از تکنیک های استفاده شده به طور مستقیم توسط یک گروه متمایز هستند، اگرچه گاهی اوقات تقاطع در این دو مجموعه تکنیک وجود دارد.

دستورالعمل زیر می تواند برای بازیابی تکنیک های استفاده شده توسط نرم افزار گروهی استفاده شود:

```python
from stix2.utils import get_type_from_id
from stix2 import Filter

def get_techniques_by_group_software(thesrc, group_stix_id):
    # get the malware, tools that the group uses
    group_uses = [
        r for r in thesrc.relationships(group_stix_id, 'uses', source_only=True)
        if get_type_from_id(r.target_ref) in ['malware', 'tool']
    ]

    # get the technique stix ids that the malware, tools use
    software_uses = thesrc.query([
        Filter('type', '=', 'relationship'),
        Filter('relationship_type', '=', 'uses'),
        Filter('source_ref', 'in', [r.source_ref for r in group_uses])
    ])

    #get the techniques themselves
    return thesrc.query([
        Filter('type', '=', 'attack-pattern'),
        Filter('id', 'in', [r.target_ref for r in software_uses])
    ])

get_techniques_by_group_software(src, "intrusion-set--f047ee18-7985-4946-8bfb-4ed754d3a0dd")
```

#### کار با اشیاء ناقص و باطل

اشیایی که دیگر برای ردیابی به عنوان بخشی از پایگاه دانش مفید نیستند، به عنوان deprecated مشخص می شوند و اشیایی که با یک شی متفاوت جایگزین می شوند، باطل می شوند. در هر دو مورد، موضوع قدیمی با یک رشته مشخص می شود (یا [KEEP_0] و یا [[KEEP] وضعیت آنها نیست. در مورد اشیاء لغو شده، یک رابطه از نوع [KEEP_2] نیز ایجاد شده است هدف قرار دادن شیء جایگزین.

بر خلاف دیگر اشیاء در مجموعه داده ها، روابط نمی تواند لغو یا حذف شود. روابط در نظر گرفته می شود که اگر یکی از اشیائی که به آن متصل شده است باطل شده یا حذف شده باشد.

##### حذف و تخریب اشیاء

اشیاء بازسازی شده و تخریب شده در پایگاه دانش نگهداری می شوند تا جریان های کاری که به آن اشیاء متکی هستند، به آن ها وابسته نیستند.
شکسته ما توصیه می کنیم که هر زمان که امکان دارد، اشیاء لغو شده و حذف شده را از دیدگاه های خود فیلتر کنید زیرا آنها هیچگاه نیستند.
طولانی تر توسط ATT & CK

ما توصیه می کنیم - نه با استفاده از فیلترهای STDX ساخته شده برای حذف اشیاء لغو شده (به عنوان مثال [KEEP_0]). این به این دلیل است که رفتار این فیلتر خاص با توجه به روش دسترسی (استفاده از داده های محلی یا دسترسی از طریق سرور TAXII) ناسازگار است. ما توصیه می کنیم از مثال کد زیر برای فیلتر کردن اشیاء لغو شده استفاده کنید. مشاهده کنید که جزئیات بیشتر است.

```python
from stix2 import Filter

def remove_revoked_deprecated(stix_objects):
    """Remove any revoked or deprecated objects from queries made to the data source"""
    # Note we use .get() because the property may not be present in the JSON data. The default is False
    # if the property is not set.
    return list(
        filter(
            lambda x: x.get("x_mitre_deprecated", False) is False and x.get("revoked", False) is False,
            stix_objects
        )
    )

mitigations = src.query([ Filter("type", "=", "course-of-action") ])
mitigations = remove_revoked_deprecated(mitigations)
```

##### گرفتن یک شی بازسازی

هنگامی که یک شی جایگزین یک شی دیگر می شود، آن را با میدان ([KEEP_0] و یک رابطه از نوع ([KEEP] ایجاد می کند که در آن [KEEP_2] جسم باطل و [KEEP_3] شی بازسازی شده است. این رابطه را می توان برای پیدا کردن شی جایگزین دنبال کرد:

```python
from stix2 import Filter

def getRevokedBy(stix_id, thesrc):
    relations = thesrc.relationships(stix_id, 'revoked-by', source_only=True)
    revoked_by = thesrc.query([
        Filter('id', 'in', [r.target_ref for r in relations]),
        Filter('revoked', '=', False)
    ])
    if revoked_by is not None:
        revoked_by = revoked_by[0]

    return revoked_by

getRevokedBy("attack-pattern--c16e5409-ee53-4d79-afdc-4099dc9292df", src)
```
