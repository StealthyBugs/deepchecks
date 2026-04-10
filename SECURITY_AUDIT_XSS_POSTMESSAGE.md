# Security Audit: XSS and postMessage Vulnerabilities in Deepchecks

**Date:** 2026-04-10
**Scope:** Production frontend code in `deepchecks/` (excluding tests, mocks, fixtures)
**Methodology:** Static analysis with source-to-sink tracing, empirical verification of Pandas Styler escaping behavior

---

## Executive Summary

The deepchecks HTML serialization pipeline has **zero HTML escaping** across all user-controlled data paths. The Python standard library `html.escape()` is never called on any user-facing string that flows into HTML output. This results in multiple stored XSS vulnerabilities exploitable through:

1. **Malicious DataFrame column/feature names** (the primary real-world attack vector)
2. **JSON deserialization of crafted check results** (via `BaseCheckResult.from_json()`)
3. **User-controlled suite names, label maps, and dataset names**

Additionally, Pandas `Styler.to_html()` -- the primary DataFrame rendering path -- does **not** escape HTML entities in cell values (empirically confirmed), creating a systemic XSS surface for all condition tables and failure tables.

---

## Confirmed Findings

### FINDING 1: Title Tag Injection via Suite/Check Name

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/utils/strings.py:152` |
| **Sink** | `template.replace('$Title', title)` |
| **Template** | `deepchecks/core/resources/suite-template-full.html:17` -- `<title>$Title</title>` |
| **Source** | `Suite(name=...)`, `CheckResult(header=...)`, or `SuiteResult.from_json()` |
| **Sanitization** | None |
| **Production-reachable** | Yes -- `save_as_html()`, `show()`, `widget_to_html_string()` |

**Source -> Sink Path:**
```
User input -> Suite(name="</title><script>alert(1)</script>")
  -> SuiteResult.name
  -> display.get_result_name(result) returns result.name
  -> strings.widget_to_html(title=name)
  -> template.replace('$Title', title)
  -> <title></title><script>alert(1)</script></title>
```

**Why sanitization fails:** No `html.escape()` is applied. The `<title>` tag is a raw text element; `</title>` closes it and subsequent markup executes.

**PoC:**
```python
from deepchecks.tabular import Suite
from deepchecks.tabular.checks import DatasetsSizeComparison
suite = Suite('</title><script>alert(document.domain)</script>', DatasetsSizeComparison())
result = suite.run(train_dataset=train, test_dataset=test)
result.save_as_html("xss.html")  # Opening xss.html triggers JS execution
```

**Fix:** Apply `html.escape(title)` before substitution at `strings.py:152`.

---

### FINDING 2: Suite Name Injected into `<h1>` Tag

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/serialization/suite_result/html.py:173` |
| **Sink** | `f'<h1{idattr}>{self.value.name}</h1>'` |
| **Source** | `Suite(name=...)` or `SuiteResult.from_json()` |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Source -> Sink Path:**
```
Suite(name="<img src=x onerror=alert(1)>")
  -> SuiteResult.name
  -> SuiteResultSerializer.prepare_header()
  -> f'<h1>{self.value.name}</h1>'
  -> raw HTML injection
```

**Fix:** `html.escape(self.value.name)` before interpolation.

---

### FINDING 3: Check Header Injected into HTML Tags + Attribute Injection

| Field | Value |
|---|---|
| **Type** | Stored XSS + HTML Attribute Injection |
| **Files** | `deepchecks/core/serialization/check_result/html.py:129-135`, `check_failure/html.py:59-67` |
| **Sink** | `f'<h4 id="{check_id}"><b>{header}</b></h4>'` |
| **Source** | `CheckResult(header=...)`, `CheckResultJson(json_dict)` where `json_dict['header']` is attacker-controlled |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Source -> Sink Path:**
```
CheckResult(header='x" onclick="alert(1)')
  -> get_header() returns raw header
  -> get_check_id() returns header.replace(' ','') + '_' + id
  -> f'<h4 id="{check_id}"><b>{header}</b></h4>'
  -> <h4 id="x"onclick="alert(1)"_id"><b>x" onclick="alert(1)</b></h4>
```

Both `<b>` body content and `id=""` attribute are injectable. The `id` attribute value comes from `get_check_id()` which strips only spaces from the header.

**Fix:** `html.escape(header)` and `html.escape(check_id, quote=True)`.

---

### FINDING 4: `linktag()` Has Zero Escaping on Text and Attributes

| Field | Value |
|---|---|
| **Type** | Stored XSS + Attribute Injection |
| **File** | `deepchecks/utils/html.py:57-58` |
| **Sink** | `f'<a {attrs}>{text}</a>'` where `attrs = ' '.join([f'{k}="{v}"' ...])` |
| **Source** | `check_result.get_header()` passed as `text`, `get_check_id()` output in `href` |
| **Sanitization** | None -- no import of any escaping function in the file |
| **Production-reachable** | Yes -- called from `aggregate_conditions()` and `create_results_dataframe()` |

**Source -> Sink Path:**
```
CheckResult(header='<script>alert(1)</script>')
  -> aggregate_conditions() at common.py:158
  -> linktag(text=check_header, href=f'#{get_check_id(output_id)}')
  -> f'<a href="#{check_id}">{text}</a>'
  -> <a href="#<script>..."><script>alert(1)</script></a>
```

**Fix:** Escape both `text` and all attribute values with `html.escape()`.

---

### FINDING 5: Pandas `Styler.to_html()` Does Not Escape HTML (Empirically Confirmed)

| Field | Value |
|---|---|
| **Type** | Stored XSS (systemic) |
| **File** | `deepchecks/core/serialization/dataframe/html.py:62-65` |
| **Sink** | `df_styler.to_html()` / `df_styler.render()` |
| **Source** | All DataFrame cell values rendered through this path |
| **Sanitization** | None -- Styler does not escape by default |
| **Production-reachable** | Yes -- primary rendering path for all condition tables and failure tables |

**Empirical confirmation:**
```python
df = pd.DataFrame({'col': ['<script>alert(1)</script>']})
html = df.style.to_html()
assert '<script>alert(1)</script>' in html  # TRUE - raw script tag present
```

This affects:
- **Condition names** (`cond_result.name`) in `aggregate_conditions()` at `common.py:169`
- **Condition details** (`cond_result.details`) at `common.py:169`
- **Exception messages** (`it.exception.html` or `str(it.exception)`) in `create_failures_dataframe()` at `common.py:255-265`
- **Check headers** passed through `linktag()` into DataFrame cells

The fallback `DataFrame.to_html()` at line 69 DOES escape, but is only reached on `ValueError` (multi-index edge case).

**Fix:** Escape user-controlled cell values before inserting into DataFrames, or apply escaping at the Styler level.

---

### FINDING 6: `handle_string()` Renders Display Strings as Raw HTML

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/serialization/check_result/html.py:281-283` |
| **Sink** | `f'<div>{item}</div>'` |
| **Source** | String items in `CheckResult.display` list |
| **Sanitization** | None |
| **Production-reachable** | Yes |

String display items are intentionally HTML (checks use `<span>`, `<b>`, `<br>` in display strings). The vulnerability is that **user-controlled data is interpolated into these HTML strings without escaping** in check implementations. Examples:

- `deepchecks/utils/abstracts/feature_drift.py:152-156` -- column names in `<span>` tags
- `deepchecks/utils/abstracts/confusion_matrix_abstract.py:76-78` -- class names in `<b>` tags
- `deepchecks/utils/abstracts/weak_segment_abstract.py:154-167` -- feature names as DisplayMap keys

**PoC:**
```python
import pandas as pd
# Column named with XSS payload
df = pd.DataFrame({'<img src=x onerror=alert(1)>': [1, 2, 3]})
# When a check processes this DataFrame, the column name flows unescaped
# into display HTML strings and renders as live HTML
```

**Fix:** Escape user-controlled data (column names, class names, feature names) with `html.escape()` before interpolating into HTML strings in check implementations.

---

### FINDING 7: DisplayMap Keys Rendered as Raw HTML

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/serialization/check_result/html.py:353-377` |
| **Sink** | `template.format(name=k, ...)` where template contains `<summary><strong>{name}</strong></summary>` |
| **Source** | DisplayMap dictionary keys (often dataset feature/column names) |
| **Sanitization** | None |
| **Production-reachable** | Yes -- used by weak_segments_performance, under_annotated_segments |

**Source -> Sink Path:**
```
DataFrame column "Feature1" = '<img src=x onerror=alert(1)>'
  -> weak_segment_abstract.py:154: tab_name = f'{segment["Feature1"]} vs {segment["Feature2"]}'
  -> DisplayMap key = '<img src=x onerror=alert(1)> vs Feature2'
  -> handle_display_map: template.format(name=key)
  -> <summary><strong><img src=x onerror=alert(1)> vs Feature2</strong></summary>
```

**Fix:** `html.escape(k)` before using as template parameter.

---

### FINDING 8: Exception Messages in `<p>` Tag Without Escaping

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/serialization/check_failure/html.py:73-75` |
| **Sink** | `f'<p style="color:red">{self.value.exception}</p>'` |
| **Source** | Exception messages that may contain user-controlled data (column names, parameter values) |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Source -> Sink Path:**
```
DataFrame with column '<script>alert(1)</script>'
  -> DatasetValidationError(f'label column {label} not found...')
  -> CheckFailure wraps exception
  -> CheckFailureSerializer.prepare_error_message()
  -> f'<p style="color:red">{exception}</p>'
  -> raw script execution
```

Also applies to `DeepchecksBaseError.html` property (`errors.py:25`) which defaults to the raw message string.

**Fix:** `html.escape(str(self.value.exception))`.

---

### FINDING 9: `extra_info` Items Rendered as Raw HTML

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/serialization/suite_result/html.py:177-179` |
| **Sink** | `f'<div>{it}</div>'` for each item in `self.value.extra_info` |
| **Source** | `SuiteResult(extra_info=[...])` or `SuiteResult.from_json()` |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Fix:** `html.escape(it)` before interpolation.

---

### FINDING 10: JSON Deserialization `plt` Type -- Single-Quote Attribute Breakout

| Field | Value |
|---|---|
| **Type** | Stored XSS via Attribute Injection |
| **File** | `deepchecks/core/check_json.py:98` |
| **Sink** | `f"<img src='data:image/png;base64,{payload}'>"` |
| **Source** | `payload` field from JSON input to `from_json()` |
| **Sanitization** | None -- no base64 validation, no quote escaping |
| **Production-reachable** | Yes -- via `BaseCheckResult.from_json()` |

**Empirical confirmation:**
```python
payload = "x' onerror='alert(1)"
result = f"<img src='data:image/png;base64,{payload}'>"
# Result: <img src='data:image/png;base64,x' onerror='alert(1)'>
# The single-quote breaks out of src attribute
```

**Source -> Sink Path:**
```
Attacker JSON: {"display": [{"type": "plt", "payload": "x' onerror='alert(1)"}]}
  -> _process_jsonified_display_items()
  -> f"<img src='data:image/png;base64,{payload}'>"
  -> <img src='data:image/png;base64,x' onerror='alert(1)'>
  -> handle_string() wraps in <div>, renders in browser
```

**Fix:** Validate `payload` is valid base64, and use double-quotes with `html.escape()`: `f'<img src="data:image/png;base64,{html.escape(payload)}"/>'`.

---

### FINDING 11: JSON Deserialization `html` Type -- Raw HTML Pass-Through

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/core/check_json.py:89-90` |
| **Sink** | `output.append(payload)` -- raw HTML added to display list |
| **Source** | `payload` field from JSON input |
| **Sanitization** | None |
| **Production-reachable** | Yes -- via `BaseCheckResult.from_json()` |

**Source -> Sink Path:**
```
Attacker JSON: {"display": [{"type": "html", "payload": "<script>alert(1)</script>"}]}
  -> _process_jsonified_display_items(): output.append(payload)
  -> handle_string(): f'<div>{item}</div>'
  -> <div><script>alert(1)</script></div>
```

**Fix:** Sanitize HTML payloads with an allowlist-based sanitizer, or document that `from_json()` must only be used with trusted input.

---

### FINDING 12: Vision Module -- Image IDs and Label Map Values in HTML

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **Files** | `deepchecks/vision/vision_data/vision_data.py:313, 332-333, 350-351` |
| **Sink** | `f'<p style="...">{image_id}</p>'`, `f'<p style="...">{self.label_map[label]}</p>'` |
| **Source** | `VisionData` image identifiers and user-provided `label_map: Dict[int, str]` |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Fix:** `html.escape()` on `image_id` and `self.label_map[label]`.

---

### FINDING 13: Vision Module -- Label Names in `new_labels` Check

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/vision/checks/train_test_validation/new_labels.py:122-128, 216` |
| **Sink** | `HTML_TEMPLATE.format(label_name=class_name, dataset_name=context.test.name, ...)` |
| **Template** | `<h3><b>Label  "{label_name}"</b></h3>` |
| **Source** | `label_map` values (user-provided), `dataset_name` (user-provided) |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Fix:** `html.escape()` on all template parameters.

---

### FINDING 14: NLP Module -- Token Text in HTML

| Field | Value |
|---|---|
| **Type** | Stored XSS |
| **File** | `deepchecks/nlp/utils/token_classification_utils.py:42-43` |
| **Sink** | `f'<b>{word}</b>'` where `word` is from `TextData.tokenized_text` |
| **Source** | User text tokens |
| **Sanitization** | None |
| **Production-reachable** | Yes |

**Fix:** `html.escape(word)` before wrapping in `<b>` tags.

---

## postMessage Handler Summary

### Handler 1: setImmediate Polyfill

| Field | Value |
|---|---|
| **Files** | `widgets-embed.js:10556-10558`, `widgets-embed-amd.js:1909-1911` (and duplicates in both files) |
| **Origin check** | `e.source === window` (same-window check) |
| **Source check** | Message must start with random prefix `setImmediate$<Math.random()>$` |
| **Sensitive actions** | Calls a scheduled callback function by numeric ID |
| **Data exposed** | None |
| **Bypass attempts** | The random prefix (`setImmediate$0.12345...$`) prevents guessing. `e.source === window` prevents cross-origin frames from triggering. |
| **Verdict** | **NOT EXPLOITABLE** -- standard setImmediate polyfill pattern with sufficient protections. |

Note: Also contains `new Function(""+t)` for non-function setImmediate args, but input is from application code, not external.

### Handler 2: React Scheduler

| Field | Value |
|---|---|
| **Files** | `widgets-embed.js:13445`, `widgets-embed-amd.js` (React internals) |
| **Origin check** | Internal port messaging via `MessageChannel` |
| **Source check** | N/A (port-based, not window.postMessage) |
| **Sensitive actions** | Schedules React rendering work |
| **Data exposed** | None |
| **Bypass attempts** | MessageChannel ports are not accessible cross-origin. |
| **Verdict** | **NOT EXPLOITABLE** -- internal React scheduling mechanism. |

### Handler 3: Lumino Widget Messaging

| Field | Value |
|---|---|
| **Files** | Throughout `widgets-embed.js` and `widgets-embed-amd.js` |
| **Type** | Internal messaging system (`ee.c.postMessage(widget, msg)`) -- NOT `window.postMessage` |
| **Verdict** | **NOT APPLICABLE** -- this is an internal object messaging system, not the browser postMessage API. |

### Overall postMessage Assessment

All `window.addEventListener('message', ...)` handlers in the bundled JavaScript are from standard library polyfills (setImmediate, React scheduler) with adequate origin/source validation. **No exploitable postMessage vulnerabilities found.**

---

## Summary of All Findings

| # | Type | File | Line | Severity | Vector |
|---|---|---|---|---|---|
| 1 | Stored XSS | `utils/strings.py` | 152 | **High** | `<title>` breakout via suite/check name |
| 2 | Stored XSS | `suite_result/html.py` | 173 | **High** | Suite name in `<h1>` |
| 3 | Stored XSS + Attr Injection | `check_result/html.py` | 129-135 | **High** | Check header in `<h4>` + `id` attr |
| 4 | Stored XSS + Attr Injection | `utils/html.py` | 57-58 | **High** | `linktag()` text + attrs unescaped |
| 5 | Stored XSS (systemic) | `dataframe/html.py` | 62-65 | **High** | Styler.to_html() no escaping |
| 6 | Stored XSS | `check_result/html.py` | 281-283 | **High** | `handle_string()` raw HTML |
| 7 | Stored XSS | `check_result/html.py` | 353-377 | **High** | DisplayMap keys as raw HTML |
| 8 | Stored XSS | `check_failure/html.py` | 73-75 | **High** | Exception messages in `<p>` |
| 9 | Stored XSS | `suite_result/html.py` | 177-179 | **Medium** | extra_info in `<div>` |
| 10 | Stored XSS (Attr) | `check_json.py` | 98 | **High** | plt payload single-quote breakout |
| 11 | Stored XSS | `check_json.py` | 89-90 | **High** | Raw HTML from JSON |
| 12 | Stored XSS | `vision/vision_data.py` | 313,332-333 | **High** | image_id + label_map values |
| 13 | Stored XSS | `vision/.../new_labels.py` | 122-128 | **High** | Label names in template |
| 14 | Stored XSS | `nlp/.../token_classification_utils.py` | 42-43 | **Medium** | Token text in `<b>` |

---

## Root Cause

The entire HTML serialization pipeline performs raw string interpolation (f-strings, `.format()`, `.replace()`) without ever calling `html.escape()` or any equivalent. The only use of `html.escape()` in the entire codebase is for iframe `srcdoc` attribute escaping in `display.py:392`.

String display items are intentionally treated as raw HTML (checks embed `<span>`, `<b>`, `<br>` etc.), but user-controlled data (column names, feature names, label names, class names, exception messages) is interpolated into these HTML strings without escaping at the source.

## Additional Notable Finding (Outside XSS Scope)

### `jsonpickle.loads()` Without Safe Mode -- Potential RCE

| Field | Value |
|---|---|
| **Type** | Unsafe Deserialization |
| **Files** | `check_result.py:86`, `check_json.py:58,125`, `suite.py:521`, `utils/json_utils.py:37` |
| **Pattern** | `jsonpickle.loads(json_dict)` without `safe=True` |
| **Risk** | If attacker controls JSON input to `from_json()`, they can instantiate arbitrary Python objects via `py/object` markers, leading to RCE |
| **Note** | While `jsonpickle.dumps()` is called with `unpicklable=False` (good), `loads()` still honors type markers if present in input |

This is outside the XSS audit scope but was discovered during analysis and warrants immediate attention.

---

## Recommended Fixes

1. **Centralized escaping utility**: Create a `safe_interpolate()` function that applies `html.escape()` to all parameters
2. **Fix `linktag()`**: Escape `text` and all attribute values
3. **Fix template substitution**: `html.escape(title)` before `$Title` replacement
4. **Fix all `f'<tag>{user_data}</tag>'` patterns**: Apply `html.escape()` in serializers
5. **Fix DataFrame rendering**: Escape user-controlled values before inserting into DataFrames that use Styler
6. **Fix `check_json.py`**: Validate base64 for plt type; sanitize HTML payloads
7. **Fix check implementations**: Escape column names, feature names, label names before HTML interpolation
8. **Add CSP meta tag**: To generated HTML for defense-in-depth
9. **Fix `jsonpickle.loads()`**: Pass `safe=True` or switch to `json.loads()` since data is serialized with `unpicklable=False`
