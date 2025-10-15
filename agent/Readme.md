1. Clone hoặc tải thư mục agent về máy:
cd apache-agent

2. Xây dựng image Docker:
docker build -t apache-agent:latest .

3. Cách chạy môi trường demo – Docker
- Chạy trực tiếp trong môi trường có Apache
docker run --rm \
  -v /etc/apache2:/etc/apache2:ro \
  -v /var/www:/var/www:ro \
  -v /var/log/apache2:/var/log/apache2:ro \
  -v /var/run/apache2:/var/run/apache2:ro \
  -v /etc/ssl:/etc/ssl:ro \
  -e APACHE_ROOT=/etc/apache2 \
  apache-agent:latest > report_full.json
  ____________________________________________________________________________

  Cách triển khai agent trong môi trường thực:
  # SecRuleMap — Hướng dẫn SSH an toàn từ Kali (agent) đến Ubuntu (server)
_Hướng dẫn ngắn gọn, chuyên nghiệp để cấu hình kết nối SSH bằng key, triển khai và chạy script agent thu thập/quét file cấu hình Apache trên máy Ubuntu mục tiêu._

---

## Tổng quan
Tài liệu này mô tả các bước cần thiết để:
- Cài đặt SSH trên máy Ubuntu (server).
- Tạo user `agent` với xác thực bằng SSH key.
- Triển khai và chạy script agent (`apache_agent.py`) từ Kali (máy tấn công/kiểm thử).
- Các lưu ý về quyền truy cập, môi trường Python ảo (venv), firewall và an toàn.

> Ví dụ trong tài liệu dùng IP máy target: `192.168.1.17` và đường dẫn script trên Kali:  
> `$HOME/project of agent/agent/apache_agent.py`

---

## Yêu cầu trước
- Quyền sudo trên máy Ubuntu target.
- Quyền truy cập SSH (TCP/22) giữa Kali và Ubuntu (hoặc port SSH bạn dùng).
- Python 3 trên Ubuntu (>=3.8 khuyến nghị).
- Trên Kali: sẵn ssh-keygen, scp, ssh.

---

## 1. Thiết lập Ubuntu (server)

### 1.1 Cài đặt và bật SSH server
```bash
sudo apt update
sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo ss -tunlp | grep ssh   # kiểm tra sshd đang lắng nghe
```

### 1.2 Tạo user chuyên dụng cho agent
```bash
sudo adduser --disabled-password --gecos "" agent
# nếu muốn đặt mật khẩu:
sudo passwd agent
```

### 1.3 Tạo thư mục .ssh và đặt quyền
```bash
sudo mkdir -p /home/agent/.ssh
sudo chown agent:agent /home/agent/.ssh
sudo chmod 700 /home/agent/.ssh
```

### 1.4 Cấu hình firewall (ufw)
```bash
sudo ufw allow OpenSSH
sudo ufw enable
# kiểm tra:
sudo ufw status verbose
```

---

## 2. Thiết lập xác thực bằng SSH key (Kali → Ubuntu)

### 2.1 Tạo SSH key trên Kali (nếu chưa có)
```bash
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_agent -C "agent@kali"
```

### 2.2 Chép public key lên Ubuntu
Trên Kali:
```bash
scp ~/.ssh/id_ed25519_agent.pub agent@192.168.1.17:/home/agent/.ssh/authorized_keys_tmp
```

Trên Ubuntu (dùng sudo để gộp vào authorized_keys và sửa quyền):
```bash
sudo mkdir -p /home/agent/.ssh
sudo chown agent:agent /home/agent/.ssh
sudo chmod 700 /home/agent/.ssh

# Append public key vào authorized_keys (chạy dưới quyền root)
sudo sh -c 'cat /home/agent/.ssh/authorized_keys_tmp >> /home/agent/.ssh/authorized_keys'

# Đặt quyền đúng cho file authorized_keys
sudo chown agent:agent /home/agent/.ssh/authorized_keys
sudo chmod 600 /home/agent/.ssh/authorized_keys

# (Tùy chọn) xóa file tạm
sudo rm /home/agent/.ssh/authorized_keys_tmp
```

### 2.3 Kiểm tra kết nối SSH từ Kali
```bash
ssh -i ~/.ssh/id_ed25519_agent agent@192.168.1.17
# nếu đăng nhập thành công, bạn sẽ có shell của user agent trên Ubuntu
```

---

## 3. Cấp quyền cần thiết cho agent (ví dụ đọc key TLS)
Nếu agent cần truy cập vào thư mục chứa khóa/ chứng chỉ (ví dụ `/etc/ssl/private`), thêm `agent` vào nhóm phù hợp:
```bash
sudo usermod -aG ssl-cert agent
```
> Kiểm tra: `groups agent` để xác nhận.

---

## 4. Triển khai script agent lên server

### 4.1 Copy script từ Kali lên Ubuntu
Giả sử script ở Kali: `$HOME/project of agent/agent/apache_agent.py`
```bash
scp -i ~/.ssh/id_ed25519_agent "$HOME/project of agent/agent/apache_agent.py" agent@192.168.1.17:/home/agent/apache_agent.py
```

### 4.2 Kiểm tra file trên server
SSH vào Ubuntu rồi:
```bash
ssh -i ~/.ssh/id_ed25519_agent agent@192.168.1.17
ls -l /home/agent/apache_agent.py
```

---

## 5. Chạy script agent (ví dụ tạm thời, trực tiếp)

Trên Ubuntu (shell của user `agent`), chạy:
```bash
# chạy thu thập với APACHE_ROOT chỉ định, xuất kết quả ra JSON
sudo APACHE_ROOT=/etc/apache2 python3 /home/agent/apache_agent.py > /home/agent/apache_report.json

# xem kết quả
cat /home/agent/apache_report.json
```
> Ghi chú: nếu script cần quyền root để đọc một số file, dùng `sudo` khi chạy. Cân nhắc hạn chế quyền sudo — chỉ cấp quyền cần thiết cho `agent`.

---

## 6. Cài đặt môi trường Python ảo (khuyến nghị)
Để tránh cài thư viện toàn hệ thống, tạo virtualenv cho agent.
```bash
# cài dependencies nếu cần
sudo apt install -y python3-venv python3-pip

# tạo và kích hoạt venv (dưới user agent)
python3 -m venv ~/apache_agent_venv
. ~/apache_agent_venv/bin/activate

# cập nhật pip và cài thư viện cần thiết
pip install --upgrade pip
pip install paramiko  # ví dụ lib cần dùng

# tắt venv khi xong
deactivate
```
Nếu admin không cho dùng pip, có thể dùng package apt (ví dụ `sudo apt install -y python3-paramiko`).

Chạy script trong venv:
```bash
. ~/apache_agent_venv/bin/activate
sudo APACHE_ROOT=/etc/apache2 python3 /home/agent/apache_agent.py > /home/agent/apache_report.json
deactivate
```

---

## 7. Lệnh test nhanh
Trên Ubuntu, để test chạy ngay file agent:
```bash
python3 /home/agent/apache_agent.py > /home/agent/report.json
cat /home/agent/report.json
```

---

## 8. Gợi ý bảo mật & vận hành

- **Hạn chế quyền sudo**: tránh cho `agent` quyền root toàn phần. Nếu cần vài lệnh sudo, cấu hình `/etc/sudoers.d/agent` để chỉ cho phép các lệnh cụ thể.
- **SSH hardening**: tắt đăng nhập bằng mật khẩu (`PasswordAuthentication no`) trong `/etc/ssh/sshd_config` sau khi đã xác thực key hoạt động ổn định.
- **Giám sát và logging**: lưu log cho các lần truy cập agent, kiểm tra `auth.log` để phát hiện hành vi bất thường.
- **Quyền file**: chỉ cấp quyền đọc những file cần thiết; không thêm `agent` vào nhóm có quyền ghi không cần thiết.
- **Cập nhật**: giữ hệ điều hành và OpenSSH cập nhật các bản vá bảo mật.

---

## 9. Khắc phục sự cố thường gặp

- **Không thể SSH**: kiểm tra `ss -tunlp | grep ssh` và `sudo ufw status`, cũng như tường lửa mạng.
- **Public key không được chấp nhận**: kiểm tra quyền `/home/agent/.ssh` (700) và `/home/agent/.ssh/authorized_keys` (600) — SSH sẽ từ chối nếu quyền quá lỏng.
- **Script báo lỗi quyền**: chạy với `sudo` nếu script cần đọc file thuộc root; xem lại yêu cầu quyền trong script.
- **Thiếu thư viện Python**: kích hoạt venv và `pip install` các gói cần thiết, hoặc dùng `sudo apt install` phiên bản hệ thống.

---

## 10. Ví dụ nhanh (tóm tắt các lệnh cần thiết)
```bash
# trên Kali: tạo key và copy public key
ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519_agent -C "agent@kali"
scp ~/.ssh/id_ed25519_agent.pub agent@192.168.1.17:/home/agent/.ssh/authorized_keys_tmp

# trên Ubuntu: chỉnh quyền và gộp key
sudo mkdir -p /home/agent/.ssh
sudo chown agent:agent /home/agent/.ssh
sudo chmod 700 /home/agent/.ssh
sudo sh -c 'cat /home/agent/.ssh/authorized_keys_tmp >> /home/agent/.ssh/authorized_keys'
sudo chown agent:agent /home/agent/.ssh/authorized_keys
sudo chmod 600 /home/agent/.ssh/authorized_keys

# từ Kali: kiểm tra SSH
ssh -i ~/.ssh/id_ed25519_agent agent@192.168.1.17

# copy script và chạy
scp -i ~/.ssh/id_ed25519_agent "$HOME/project of agent/agent/apache_agent.py" agent@192.168.1.17:/home/agent/apache_agent.py
ssh -i ~/.ssh/id_ed25519_agent agent@192.168.1.17
sudo APACHE_ROOT=/etc/apache2 python3 /home/agent/apache_agent.py > /home/agent/apache_report.json
cat /home/agent/apache_report.json
```

---

## License & liên hệ
- Tài liệu này là hướng dẫn nội bộ; tùy chỉnh theo chính sách bảo mật của tổ chức bạn.
- Nếu cần hỗ trợ chi tiết (ví dụ: cấu hình `sudoers`, service unit để chạy agent định kỳ, hoặc triển khai qua systemd), vui lòng mô tả thêm yêu cầu — mình sẽ cung cấp mẫu cấu hình tương ứng.
