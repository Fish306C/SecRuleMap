

# rules

Đây là bộ rule mẫu thực tế, tức là dữ liệu mà tool sẽ quét.

Chứa các rule YAML cụ thể cho:

headers/ → OWASP headers (HSTS, X-Frame-Options…)

webserver/ → config Nginx/Apache theo CIS benchmark

resources/ → file lộ, backup, .git, .env

components/ → thành phần CMS/plugin và CVE

Nói cách khác: đây là rule content mà tool sẽ áp dụng, là “thực thể” mà module src/mini_zap/rules/loader.py sẽ load.