BASE='https://a7c6d9e1.proxy.coursestack.com'
TOK='a7c6d9e1-9f06-4c02-9891-7cc13f9568d4_1_a289dfdf952c47ab4895fb042c238501bcc99a63f656b46a5567e56238ed658f'
curl -k --http1.1 -sSIL -H "Cookie: token=$TOK" "$BASE/robots.txt"
curl -k --http1.1 -sSL  -H "Cookie: token=$TOK" "$BASE/robots.txt"

BASE='https://a7c6d9e1.proxy.coursestack.com'
TOK='a7c6d9e1-9f06-4c02-9891-7cc13f9568d4_1_a289dfdf952c47ab4895fb042c238501bcc99a63f656b46a5567e56238ed658f'

# Save headers and body separately (nice for write-ups)
curl -k --http1.1 -sS \
  -H "Cookie: token=$TOK" \
  -D robots.headers.txt \
  -o robots.raw.txt \
  "$BASE/robots.txt"

# Strip blank lines and keep only meaningful records
grep -Ei '^(User-agent|Allow|Disallow|Sitemap|#)' robots.raw.txt \
  | sed '/^[[:space:]]*$/d' > robots.txt

# Peek without scrolling
nl -ba robots.txt
