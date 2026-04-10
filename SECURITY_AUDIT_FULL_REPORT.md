# Security Audit Report: deepchecks/deepchecks

**Date:** 2026-04-10  
**Methodology:** Multi-agent static analysis with 12+ parallel specialized agents, empirical verification  
**Agents Used:** A1 (Endpoints), A2 (Deserialization), A3 (Code Injection), A4 (XSS), A5 (SSTI), A6 (Dependencies), A7 (check_json.py), A8 (Vision/NLP), A9 (DataFrame), A10 (Triage), A11 (Display), A12 (Conditions)

---

## Phase 1: Repository Assessment

### Architecture

**deepchecks/deepchecks** is a Python ML validation library. It is **NOT** a web application.

| Component | Present? | Notes |
|---|---|---|
| Web server (Flask/FastAPI/Django/etc.) | **NO** | Zero HTTP endpoints |
| REST API / GET routes | **NO** | No request handlers of any kind |
| Database access (SQL) | **NO** | No SQL queries |
| JWT authentication | **NO** | No auth system |
| Server-side templates (Jinja2/Mako) | **NO** | No template engines |
| HTML report generation | **YES** | Primary attack surface |
| JSON deserialization (jsonpickle) | **YES** | Critical RCE vector |
| Telemetry | Client-only | Outbound HTTPS GET to hardcoded URL |

### Related Repositories

| Repository | Purpose | Server Components? |
|---|---|---|
| `deepchecks/monitoring` | ML monitoring (proprietary + OSS) | Yes (FastAPI backend) - NOT available for analysis |
| `deepchecks/monitoring-oss` | OSS version of monitoring | Yes - NOT available for analysis |

**Selection:** Only `deepchecks/deepchecks` (this repo) is available for analysis. The monitoring repo (which would have the actual web server surfaces) is referenced but not cloned.

### GET Surface Inventory

**There are ZERO GET endpoints in this repository.** The library has no web server, no HTTP request handlers, no API routes. The vulnerability classes that apply are:

- **RCE via unsafe deserialization** (jsonpickle.loads)
- **Code injection** (through deserialized payloads)
- **XSS** (in generated HTML reports opened in browsers)
- **Template-adjacent injection** (format strings with user data into HTML)

SQL injection, JWT bypass, SSTI, and request smuggling are **not applicable** to this codebase.

---

## Phase 4: All Findings

### CRITICAL: Unsafe Deserialization → Remote Code Execution

---

#### Finding C1: `jsonpickle.loads()` in `BaseCheckResult.from_json()`

| Field | Value |
|---|---|
| **Vulnerability class** | Code injection / RCE (unsafe deserialization) |
| **File** | `deepchecks/core/check_result.py:86` |
| **Endpoint** | Public API: `BaseCheckResult.from_json(json_string)` |
| **Parameter** | `json_dict` (str) - caller-supplied JSON |
| **Severity** | **CRITICAL** |

**Evidence:**
```python
# check_result.py:86
json_dict = jsonpickle.loads(json_dict)
```

**Why vulnerable:** `jsonpickle.loads()` deserializes arbitrary Python objects when JSON contains `py/object`, `py/reduce`, or similar markers. No `safe=True` parameter is passed (and jsonpickle's safe mode is limited). Any application calling `from_json()` with untrusted input enables RCE.

**Exploitability:** NOT GET-triggered (no web endpoints). Triggered by: loading untrusted `.json` result files, processing results from untrusted APIs, or shared notebook outputs.

**PoC payload:**
```python
from deepchecks.core.check_result import BaseCheckResult
payload = '{"py/reduce": [{"py/type": "os.system"}, {"py/tuple": ["id > /tmp/pwned"]}]}'
BaseCheckResult.from_json(payload)  # Executes 'id > /tmp/pwned'
```

**Fix:** Replace `jsonpickle.loads()` with `json.loads()`. Since `jsonpickle.dumps(unpicklable=False)` is used for serialization, the output is standard JSON.

---

#### Finding C2: `jsonpickle.loads()` in `CheckResultJson.__init__()`

| Field | Value |
|---|---|
| **Vulnerability class** | Code injection / RCE |
| **File** | `deepchecks/core/check_json.py:58` |
| **Endpoint** | `CheckResultJson(json_string)`, also reached via `BaseCheckResult.from_json()` |
| **Severity** | **CRITICAL** |

**Evidence:** `deepchecks/core/check_json.py:58`: `json_dict = jsonpickle.loads(json_dict)`

Same vulnerability class as C1. Reachable through the from_json dispatch chain.

---

#### Finding C3: `jsonpickle.loads()` in `CheckFailureJson.__init__()`

| Field | Value |
|---|---|
| **Vulnerability class** | Code injection / RCE |
| **File** | `deepchecks/core/check_json.py:125` |
| **Endpoint** | `CheckFailureJson(json_string)`, also reached via `BaseCheckResult.from_json()` |
| **Severity** | **CRITICAL** |

**Evidence:** `deepchecks/core/check_json.py:125`: `json_dict = jsonpickle.loads(json_dict)`

---

#### Finding C4: `jsonpickle.loads()` in `SuiteResult.from_json()`

| Field | Value |
|---|---|
| **Vulnerability class** | Code injection / RCE |
| **File** | `deepchecks/core/suite.py:521` |
| **Endpoint** | Public API: `SuiteResult.from_json(json_string)` |
| **Severity** | **CRITICAL** |

**Evidence:** `deepchecks/core/suite.py:521`: `json_dict = jsonpickle.loads(json_res)`

**Note:** This call is unconditional (no `isinstance(str)` guard). Double jeopardy: after initial deserialization, sub-results are also passed to `BaseCheckResult.from_json()`.

---

#### Finding C5: `jsonpickle.loads()` in `json_utils.from_json()`

| Field | Value |
|---|---|
| **Vulnerability class** | Code injection / RCE |
| **File** | `deepchecks/utils/json_utils.py:37` |
| **Endpoint** | Public API: `deepchecks.utils.json_utils.from_json(json_string)` |
| **Severity** | **CRITICAL** |

**Evidence:** `deepchecks/utils/json_utils.py:37`: `json_dict = jsonpickle.loads(json_dict)`

Top-level convenience function that dispatches to the other from_json methods.

---

### HIGH: XSS via HTML Generation (Stored XSS)

---

#### Finding H1: Raw HTML pass-through from JSON deserialization

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/check_json.py:89-90` |
| **Source** | `record['payload']` from deserialized JSON |
| **Sink** | `output.append(payload)` → `handle_string()` → `f'<div>{item}</div>'` |
| **Severity** | **HIGH** |

**Evidence:**
```python
# check_json.py:89-90
if display_type == 'html':
    output.append(payload)  # Raw HTML from JSON, zero sanitization
```

**Why vulnerable:** The payload from JSON is appended as a raw string to the display list. When rendered via `handle_string()` at `check_result/html.py:283`, it becomes `<div>{payload}</div>` without escaping. An attacker controlling the JSON can inject `<script>` tags.

---

#### Finding H2: Single-quote attribute breakout in `plt` display type

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored, attribute injection) |
| **File** | `deepchecks/core/check_json.py:98` |
| **Source** | `record['payload']` from JSON |
| **Sink** | `f"<img src='data:image/png;base64,{payload}'>"` |
| **Severity** | **HIGH** |

**Evidence:**
```python
# check_json.py:98
output.append((f'<img src=\'data:image/png;base64,{payload}\'>'))
```

**Empirically confirmed:** Payload `x' onerror='alert(1)` produces: `<img src='data:image/png;base64,x' onerror='alert(1)'>` — the single-quote breaks out of the `src` attribute.

No base64 validation is performed on the payload.

---

#### Finding H3: Suite name in `<h1>` without escaping

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/suite_result/html.py:173` |
| **Source** | `Suite(name=user_input)` or `SuiteResult.from_json()` |
| **Sink** | `f'<h1{idattr}>{self.value.name}</h1>'` |
| **Severity** | **HIGH** |

---

#### Finding H4: Check header in `<h4>` + attribute injection via `id`

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) + HTML attribute injection |
| **File** | `deepchecks/core/serialization/check_result/html.py:129-135` |
| **Source** | `CheckResult(header=...)`, `CheckResultJson` from JSON |
| **Sink** | `f'<h4 id="{check_id}"><b>{header}</b></h4>'` |
| **Severity** | **HIGH** |

`check_id` at `check_result.py:110` uses unsanitized header: `f'{header}_{unique_id}'`. A `"` in the header breaks the `id` attribute.

---

#### Finding H5: `linktag()` zero escaping on text and attributes

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) + attribute injection |
| **File** | `deepchecks/utils/html.py:57-58` |
| **Source** | `check_result.get_header()` (check names/headers from JSON) |
| **Sink** | `f'<a {attrs}>{text}</a>'` |
| **Severity** | **HIGH** |

Neither `text` nor attribute values are HTML-escaped. Called from `aggregate_conditions()` at `common.py:158` and `create_results_dataframe()` at `common.py:217`.

---

#### Finding H6: Exception messages in `<p>` tag

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_failure/html.py:75` |
| **Source** | `CheckFailureJson(json_dict)` → `self.exception = json_dict.get('exception')` |
| **Sink** | `f'<p style="color:red">{self.value.exception}</p>'` |
| **Severity** | **HIGH** |

---

#### Finding H7: CheckFailure header in `<title>` tag (breakout)

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_failure/html.py:52` |
| **Source** | `self.value.get_header()` from JSON |
| **Sink** | `f'<head><title>{header}</title></head>'` |
| **Severity** | **HIGH** |

A header containing `</title><script>alert(1)</script>` breaks out of the `<title>` element.

---

#### Finding H8: `$Title` template injection in suite HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/utils/strings.py:152` |
| **Source** | `title` from `get_result_name()` → `result.name` or `result.get_header()` |
| **Sink** | `template.replace('$Title', title)` → `<title>$Title</title>` |
| **Severity** | **HIGH** |

---

#### Finding H9: `handle_string()` renders display strings as raw HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_result/html.py:281-283` |
| **Source** | String display items containing column names, feature names |
| **Sink** | `f'<div>{item}</div>'` |
| **Severity** | **HIGH** |

User-controlled data (DataFrame column names) flow into display strings. Example at `feature_drift.py:154`: `f'score: {not_enough_samples}</span>'` where `not_enough_samples` contains column names.

---

#### Finding H10: DisplayMap keys as raw HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_result/html.py:353-377` |
| **Source** | DataFrame column names → `weak_segment_abstract.py:154`: `tab_name = f'{segment["Feature1"]} vs {segment["Feature2"]}'` |
| **Sink** | `template.format(name=k, ...)` → `<summary><strong>{name}</strong></summary>` |
| **Severity** | **HIGH** |

---

#### Finding H11: Pandas Styler.to_html() does NOT escape HTML (systemic)

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored, systemic) |
| **File** | `deepchecks/core/serialization/dataframe/html.py:62-65` |
| **Source** | All DataFrame cell values: condition names, details, check headers, exception messages |
| **Sink** | `df_styler.to_html()` / `df_styler.render()` |
| **Severity** | **HIGH** |

**Empirically confirmed:** `pd.DataFrame({'col': ['<script>alert(1)</script>']}).style.to_html()` passes script tags through unescaped.

Affects: condition details containing column names (confirmed at `drift.py:612-624`), exception messages, check headers.

---

#### Finding H12: Vision image_id in HTML without escaping

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/vision/vision_data/vision_data.py:313` |
| **Source** | `batch.numpy_image_identifiers` (user-provided) |
| **Sink** | `f'<p style="overflow-wrap: anywhere;font-size:2em;">{image_id}</p>'` |
| **Severity** | **HIGH** |

---

#### Finding H13: Vision label_map values in HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/vision/vision_data/vision_data.py:332-333, 350-351` |
| **Source** | `self.label_map[label]` (user-provided `Dict[int, str]`) |
| **Sink** | `f'<p style="...">{self.label_map[label]}</p>'` |
| **Severity** | **HIGH** |

---

#### Finding H14: Vision new_labels check - label names in template

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/vision/checks/train_test_validation/new_labels.py:122-128` |
| **Source** | `class_name` from `label_map` values |
| **Sink** | `HTML_TEMPLATE.format(label_name=class_name, ...)` → `<h3><b>Label "{label_name}"</b></h3>` |
| **Severity** | **HIGH** |

---

#### Finding H15: NLP token text in `<b>` tags

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/nlp/utils/token_classification_utils.py:42-43` |
| **Source** | `word` from `TextData.tokenized_text` (user text) |
| **Sink** | `f'<b>{word}</b>'` |
| **Severity** | **MEDIUM** |

---

#### Finding H16: Confusion matrix class names in HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/utils/abstracts/confusion_matrix_abstract.py:76-79` |
| **Source** | `classes_names` from prediction/label data |
| **Sink** | `f'<b>{classes_names[np.argmax(accuracy_array)]}</b>'` |
| **Severity** | **MEDIUM** |

---

### MEDIUM: Additional Findings

---

#### Finding M1: Condition details contain column names → Styler XSS

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/utils/distribution/drift.py:612-628` |
| **Source** | `not_passing_categorical_props` dict keyed by column names |
| **Sink** | `ConditionResult(details=...)` → DataFrame → `Styler.to_html()` (no escape) |
| **Severity** | **MEDIUM** |

Column names like `<img src=x onerror=alert(1)>` flow into condition details at lines 623-624: `f'... above threshold: {not_passing_categorical_props}'` and render unescaped via Styler.

---

#### Finding M2: `extra_info` items rendered as raw HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/suite_result/html.py:177-179` |
| **Source** | `SuiteResult(extra_info=[...])` or `SuiteResult.from_json()` |
| **Sink** | `f'<div>{it}</div>'` |
| **Severity** | **MEDIUM** |

---

#### Finding M3: Suite prologue contains unescaped check names

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/suite_result/html.py:155-158` |
| **Source** | `FakeCheck.name()` → `self._metadata['name']` from JSON |
| **Sink** | `prologue_version.format(names=', '.join(check_names[:3]))` |
| **Severity** | **MEDIUM** |

---

#### Finding M4: CheckFailure summary in `<p>` tag

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_failure/html.py:71` |
| **Source** | `FakeCheck.metadata()["summary"]` from JSON |
| **Sink** | `f'<p>{self.value.get_metadata()["summary"]}</p>'` |
| **Severity** | **MEDIUM** |

---

#### Finding M5: CheckResult summary in `<p>` tag

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/core/serialization/check_result/html.py:139` |
| **Source** | Check metadata summary |
| **Sink** | `f'<p>{self.value.get_metadata(with_doc_link=True)["summary"]}</p>'` |
| **Severity** | **MEDIUM** |

---

#### Finding M6: Vision property outliers - property names in template

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/vision/checks/data_integrity/abstract_property_outliers.py:177` |
| **Source** | `property_name` from check parameters |
| **Sink** | `HTML_TEMPLATE.format(prop_name=property_name, ...)` |
| **Severity** | **MEDIUM** |

---

#### Finding M7: Feature drift - column names in `<span>` display

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (stored) |
| **File** | `deepchecks/utils/abstracts/feature_drift.py:152-156` |
| **Source** | `not_enough_samples` (list of column names) |
| **Sink** | `f'score: {not_enough_samples}</span>'` → `handle_string()` |
| **Severity** | **MEDIUM** |

---

#### Finding M8: No iframe sandbox attribute

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (defense-in-depth gap) |
| **File** | `deepchecks/core/display.py:411` |
| **Evidence** | `<iframe allowfullscreen {attributes}></iframe>` — no `sandbox` attr |
| **Severity** | **LOW** |

Scripts execute freely in srcdoc content. The iframe has an opaque origin (safe from parent access), but top-level navigation is possible.

---

#### Finding M9: No Content-Security-Policy in generated HTML

| Field | Value |
|---|---|
| **Vulnerability class** | XSS (defense-in-depth gap) |
| **File** | All HTML serializers |
| **Evidence** | No CSP meta tag or header anywhere in generated HTML |
| **Severity** | **LOW** |

---

#### Finding M10: CDN scripts without SRI hashes

| Field | Value |
|---|---|
| **Vulnerability class** | Supply chain risk |
| **File** | `deepchecks/core/resources/__init__.py` |
| **Evidence** | `widgets_script()` and `jupyterlab_plotly_script()` load from unpkg.com without `integrity` attributes. `jupyterlab-plotly@^5.5.0` uses a semver range, not a pinned version. |
| **Severity** | **LOW** |

---

## De-duplication Notes

- Findings C1-C5 are distinct call sites for the same root vulnerability (jsonpickle.loads without safe mode). They are counted separately because each has a unique public API entry point.
- Findings H3-H10 share the root cause of missing `html.escape()` but affect different data sources and sinks.
- The Styler.to_html() issue (H11) amplifies multiple other findings (condition details, exception messages) by providing a systemic path for cell data to become unescaped HTML.

## Confirmed-Safe Patterns

- **iframe srcdoc escaping:** `display.py:392` correctly applies `html.escape()` to srcdoc content
- **JSON-in-script embedding:** `escape_script()` from ipywidgets correctly prevents `</script>` breakout in widget state
- **Template substitution:** `.replace()` is used instead of `.format()` for `$Title`, `$WidgetSnippet` — no format string injection possible
- **Format string safety:** All `.format()` calls use hardcoded templates with named parameters; user data is passed as values, never as the format string itself — no SSTI
- **postMessage handlers:** All `window.addEventListener('message')` handlers in bundled JS are standard library polyfills (setImmediate, React scheduler) with adequate source validation

## Why We Cannot Reach 50 Findings

This repository is a **client-side Python ML validation library**, not a web application. It has:
- **Zero HTTP endpoints** — no GET routes, no API surfaces
- **Zero SQL databases** — no SQL injection possible
- **Zero JWT/auth systems** — no JWT bypass possible
- **Zero server-side template engines** — no SSTI (format string patterns are safe)
- **Zero request handling** — no request smuggling

The 30 findings above represent the complete set of credible vulnerabilities in the approved classes. The majority are XSS in HTML report generation (a legitimate concern when processing untrusted data) and unsafe deserialization (legitimate RCE risk). Inflating to 50 would require either counting trivial variants of the same pattern or fabricating issues.

The related `deepchecks/monitoring` repository (which HAS a FastAPI backend with actual HTTP endpoints, database access, and authentication) is referenced in the README but is not available for analysis in this environment.
