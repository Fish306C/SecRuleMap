# Rule Management Module

Module này chịu trách nhiệm **xử lý và quản lý các rule YAML** được sử dụng trong quá trình quét.

- **`loader.py`** → Nạp (load) và kiểm tra tính hợp lệ (validate) của rule từ file YAML.  
- **`schemas.py`** → Định nghĩa schema, mức độ nghiêm trọng (severity) và assertion cho rule.  

---

## Cách sử dụng

### 1. Cài đặt thư viện phụ thuộc
Các thư viện cần thiết được liệt kê trong **`requirements.txt`**.  
Có thể cài đặt bằng một trong hai cách:
- Cài từng thư viện thủ công:
pip install requests tqdm
- Hoặc cài tất cả một lần:
pip install -r requirements.txt

### 2. Chạy tool
- Di chuyển vào thư mục src:
cd src
- Chạy lệnh sau để quét:
python -m mini_zap --url https://www.fptpray.com/
