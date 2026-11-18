# Payload feature definitions

These seven flags are appended after the original 13 request-only features. Both the trainer and the live gateway compute them from request text. Labels, test-case ids, and expected decisions are not inputs. Text is kept raw, percent-decoded once, percent-decoded a second time, and form-decoded. Matching is case-insensitive.

| Feature | Definition | 1 when |
|---|---|---|
| `sql_structure` | SQL statement shape | A quote is followed by `or`, or the text contains `union select`, or it contains both `select` and `--` |
| `markup_script` | HTML or script markup | The text contains a script tag, `alert(`, or an `onerror`, `onload`, `onclick`, or `onmouseover` handler |
| `path_traversal` | Parent-directory segment | After decoding, the text contains `../` or `..\` |
| `command_chain` | Shell separator followed by a command word, or a template expression | `;`, `|`, `&&`, or a backtick is followed by `cat`, `nc`, `bash`, `sh`, `cmd`, `powershell`, `wget`, or `curl`, or the text contains `{{`, `__globals__`, `__builtins__`, or `__import__` |
| `cookie_signal` | Cookie-bearing target or authority cookie | The text contains `cookie`, or a cookie name is `admin` or `role` |
| `log_control` | Log line-break encoding | The text contains `%0a`, `%0d`, a raw CR or LF, or the characters `\r` or `\n` |
| `jndi_lookup` | Lookup marker | The text contains `${jndi:` with optional internal whitespace |

The scanned text is the path, query, body, user agent, and every request header value except `User-Agent`, `Cookie`, and `Set-Cookie`. `Cookie` contributes cookie names only. `Set-Cookie` is included for `markup_script` and `jndi_lookup` only. On the training partition, benign `Set-Cookie` tokens collide with the other five patterns (article titles that contain both `Select` and `---`, the substring `cookie`, `%0d`, and `../` inside opaque tokens). They do not contain `${jndi:`.

The original 13 features keep their existing formulas and order. The candidate threshold is 0.50. A deterministic review rule can still block after an ML allow. That rule is recorded separately and is not an ML prediction.

`command_chain` includes template expressions as well as shell command chains. `jndi_lookup` reads header values because the raw LOG4J requests store `${jndi:` there, not in the URL or body. The clean CSV had dropped those values.

Half of the XSS rows in the saved training partition are `GET /forum` with an empty query and body. They contain no markup in any request field. `markup_script` stays 0 for that shape, including the path `/forum` by itself. The rows that carry a `message` query with a script tag set `markup_script` to 1.
