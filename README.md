# CTI

This repository contains the MITRE ATT&CK&reg; and CAPEC&trade; datasets expressed in STIX 2.0.
See [USAGE](USAGE.md) or [USAGE-CAPEC](USAGE-CAPEC.md) for information on using this content with [python-stix2](https://github.com/oasis-open/cti-python-stix2).

If you are looking for ATT&CK represented in STIX 2.1, please see the [attack-stix-data](https://github.com/mitre-attack/attack-stix-data) GitHub repository.
Both MITRE/CTI (this repository) and attack-stix-data will be maintained and updated with new ATT&CK releases for the foreseeable future, but the data model of attack-stix-data includes quality-of-life improvements not found on MITRE/CTI.
Please see the [attack-stix-data USAGE document](https://github.com/mitre-attack/attack-stix-data/blob/master/USAGE.md) for more information on the improved data model of that repository.

## Persian Localization

This fork includes a translation utility to generate a Persian (`fa`) version of the CTI dataset:

`scripts/translate_cti_to_persian.py`

Key features:

- Translates selected human-readable STIX fields (such as `name`, `description`, and narrative CAPEC fields)
- Keeps IDs, URLs, ATT&CK codes, and citation tokens intact
- Uses a persistent SQLite cache for faster reruns
- Writes output to a separate directory by default (safe, non-destructive)

Quick start:

```bash
# 1) smoke test on a small sample
python3 scripts/translate_cti_to_persian.py --dry-run --limit 50

# 2) full translation into translated/fa/
python3 scripts/translate_cti_to_persian.py
```

Fully free offline mode (recommended for large runs):

```bash
# one-time install
pip install argostranslate

# first run downloads en->fa model package once, then translates locally
python3 scripts/translate_cti_to_persian.py --provider argos_offline

# resume an interrupted run without rewriting translated files
python3 scripts/translate_cti_to_persian.py --provider argos_offline --skip-existing
```

Write Persian next to original keys in the main JSON files (`*_fa`), for example
`source_name` + `source_name_fa`:

```bash
python3 scripts/translate_cti_to_persian.py \
  --provider argos_offline \
  --mode suffix \
  --in-place \
  --skip-existing \
  --workers 16
```

If your Python is 3.9, use:

```bash
pip install "argostranslate==1.9.6"
```

Optional: use official Google Cloud Translation API:

```bash
export GOOGLE_TRANSLATE_API_KEY="your_api_key"
python3 scripts/translate_cti_to_persian.py --provider google_cloud
```

If your local Python cannot verify TLS certificates, pass a CA bundle explicitly:

```bash
python3 scripts/translate_cti_to_persian.py --ca-bundle /path/to/cacert.pem
```

Useful flags:

- `--mode replace` (default): writes Persian text into translated copies
- `--mode overlay`: keeps original text and stores Persian strings in `x_cti_persian_translations` as path/source/translated entries
- `--mode suffix`: keeps original text and writes sibling translated keys like `name_fa`, `description_fa`, `source_name_fa`
- `--in-place`: write directly into source JSON files
- `--datasets enterprise-attack mobile-attack ...`: limit which top-level datasets to process
- `--limit N`: process only first N files
- `--paths ...`: override translated JSON paths
- `--provider argos_offline`: fully free local translation after model install
- `--no-argos-auto-install`: disable automatic Argos model download/install
- `--argos-package-path /path/to/translate-en_fa.argosmodel`: import model from local file
- `--skip-existing`: resume interrupted runs (for in-place+suffix it skips files already containing `*_fa`)
- `--cache-provider-fallbacks google_public`: reuse existing cached translations from another provider

Performance tips:

- Increase `--workers` (for example `8` or `16`) and test on `--limit 200` first.
- Use `--skip-existing` so interrupted runs restart quickly.
- For deadlines, run datasets in parallel in separate terminals with separate caches:

```bash
# Terminal 1
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets enterprise-attack --cache-db .translation-cache/ent.sqlite3 --workers 16

# Terminal 2
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets mobile-attack ics-attack --cache-db .translation-cache/mob_ics.sqlite3 --workers 16

# Terminal 3
python3 scripts/translate_cti_to_persian.py --provider argos_offline --mode suffix --in-place --skip-existing --datasets pre-attack capec --cache-db .translation-cache/pre_capec.sqlite3 --workers 16
```

## ATT&CK

MITRE ATT&CK is a globally-accessible knowledge base of adversary tactics and techniques based on real-world observations.
The ATT&CK knowledge base is used as a foundation for the development of specific threat models and methodologies in the private sector, in government, and in the cybersecurity product and service community.

<https://attack.mitre.org>

## CAPEC

Understanding how the adversary operates is essential to effective cyber security.
CAPEC™ helps by providing a comprehensive dictionary of known patterns of attacks employed by adversaries to exploit known weaknesses in cyber-enabled capabilities.
It can be used by analysts, developers, testers, and educators to advance community understanding and enhance defenses.

- Focuses on application security
- Enumerates exploits against vulnerable systems
- Includes social engineering / supply chain
- Associated with Common Weakness Enumeration (CWE)

<https://capec.mitre.org/>

## STIX

Structured Threat Information Expression (STIX™) is a language and serialization format used to exchange cyber threat intelligence (CTI).

STIX enables organizations to share CTI with one another in a consistent and machine readable manner, allowing security communities to better
understand what computer-based attacks they are most likely to see and to anticipate and/or respond to those attacks faster and more effectively.

STIX is designed to improve many different capabilities, such as collaborative threat analysis, automated threat exchange, automated detection and response, and more.

<https://oasis-open.github.io/cti-documentation/>
