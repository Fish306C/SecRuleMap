1. Clone hoặc tải thư mục agent về máy:
cd apache-agent

2. Xây dựng image Docker:
docker build -t apache-agent:latest .

3. Cách chạy
- Chạy trực tiếp trong môi trường có Apache
docker run --rm \
  -v /etc/apache2:/etc/apache2:ro \
  -v /var/www:/var/www:ro \
  -v /var/log/apache2:/var/log/apache2:ro \
  -v /var/run/apache2:/var/run/apache2:ro \
  -v /etc/ssl:/etc/ssl:ro \
  -e APACHE_ROOT=/etc/apache2 \
  apache-agent:latest > report_full.json