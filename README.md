# SQLi Audit Tool

Công cụ dòng lệnh (CLI) phục vụ rà quét, đo lường và đánh giá lỗ hổng SQL Injection (SQLi) trên các ứng dụng web trong môi trường kiểm thử nội bộ. Dự án đi kèm một môi trường thực nghiệm (Testbed) sử dụng Flask và PostgreSQL để đối chứng độ chính xác giữa các điểm giao tiếp có lỗ hổng (Vulnerable) và an toàn (Safe).

## Mục đích

- Chuẩn hóa quy trình thu thập thông số phản hồi cơ sở (Baseline HTTP probing) trước khi thực hiện kiểm thử.
- Cung cấp kiến trúc tách biệt giữa tầng giao tiếp mạng (`core`), các bộ phát hiện lỗ hổng (`detectors`), cơ sở dữ liệu dấu hiệu nhận diện (`signatures`) và xuất báo cáo (`reporting`).
- Thiết lập môi trường kiểm thử cục bộ có kiểm soát nhằm đánh giá tỷ lệ phát hiện đúng (True Positive) và kiểm soát cảnh báo giả (False Positive) đối với các kỹ thuật:
  - **Error-based SQLi**: Nhận diện qua thông báo lỗi trả về từ hệ quản trị cơ sở dữ liệu (DBMS).
  - **Boolean-based Blind SQLi**: Nhận diện qua sự thay đổi trạng thái hoặc độ dài nội dung phản hồi.
  - **Time-based Blind SQLi**: Nhận diện qua độ trễ thời gian xử lý truy vấn (`elapsed_ms`).

## Cấu trúc dự án

```text
.
├── requirements.txt        # Danh sách thư viện phụ thuộc
├── signatures/             # Mẫu nhận diện lỗi DBMS và cấu hình payload
├── src/
│   ├── cli.py              # Giao diện dòng lệnh chính (Typer)
│   ├── core/
│   │   └── client.py       # HTTP client chuẩn hóa đo lường phản hồi (httpx)
│   ├── detectors/          # Các module kiểm thử Error-based, Boolean-based, Time-based
│   └── reporting/          # Module tổng hợp kết quả và xuất báo cáo
├── testbed/
│   ├── app.py              # Ứng dụng Flask mô phỏng các endpoint Vulnerable và Safe
│   └── setup_db.sql        # Kịch bản khởi tạo cơ sở dữ liệu PostgreSQL tối thiểu quyền
└── tests/                  # Unit tests và integration tests (pytest)
```

## Cơ chế hoạt động

1. **Đo lường cơ sở (Baseline Probing)**: [`AuditHttpClient`](src/core/client.py) thực hiện gửi HTTP request qua `httpx`, ghi nhận chính xác thời gian phản hồi bằng bộ đếm hiệu năng cao (`time.perf_counter`), mã trạng thái HTTP, độ dài nội dung và tiêu đề phản hồi vào cấu trúc dữ liệu [`HttpResponseData`](src/core/client.py).
2. **Phân tích và Đối chiếu (Detection)**: Các module trong `src/detectors/` sử dụng thông số cơ sở để so sánh sự sai lệch khi chèn các tham số kiểm thử, kết hợp đối chiếu với tập mẫu trong `signatures/`.
3. **Môi trường đối chứng (Local Testbed)**: Ứng dụng [`testbed/app.py`](testbed/app.py) cung cấp 2 nhóm endpoint chạy trên `127.0.0.1:5000`:
   - Nhóm có lỗ hổng (`/vuln/error/products`, `/vuln/blind/article`): Nối chuỗi trực tiếp vào câu lệnh SQL.
   - Nhóm an toàn (`/safe/products`, `/safe/article`): Sử dụng truy vấn tham số hóa (Parameterized Queries) và kiểm tra kiểu dữ liệu đầu vào.

## Yêu cầu hệ thống

- Python 3.10 trở lên
- PostgreSQL 14 trở lên (nếu sử dụng môi trường `testbed` cục bộ)

## Cài đặt

1. Khởi tạo và kích hoạt môi trường ảo:

```bash
python3 -m venv .venv
source .venv/bin/activate
```

2. Cài đặt các thư viện phụ thuộc:

```bash
pip install -r requirements.txt
```

## Thiết lập môi trường Testbed (Tùy chọn)

Môi trường testbed được cấu hình theo nguyên tắc quyền tối thiểu (chỉ cấp quyền `SELECT` cho tài khoản ứng dụng).

1. Khởi tạo cơ sở dữ liệu và tài khoản trên PostgreSQL:

```bash
sudo -u postgres psql -f testbed/setup_db.sql
```

2. Khởi chạy máy chủ Flask cục bộ:

```bash
python -m testbed.app
```

Máy chủ sẽ lắng nghe tại địa chỉ `http://127.0.0.1:5000`.

### Danh sách Endpoint trên Testbed

| Endpoint | Tham số | Mô tả |
| :--- | :--- | :--- |
| `GET /vuln/error/products` | `category` (mặc định: `books`) | Nối chuỗi trực tiếp, trả về lỗi PostgreSQL chi tiết (HTTP 500) khi cú pháp sai. |
| `GET /vuln/blind/article` | `id` (mặc định: `1`) | Nối chuỗi trực tiếp, ẩn lỗi SQL và chỉ trả về trạng thái tìm thấy (`200`) hoặc không (`404`). |
| `GET /safe/products` | `category` (mặc định: `books`) | Sử dụng Parameterized Query (`%s`). |
| `GET /safe/article` | `id` (mặc định: `1`) | Kiểm tra định dạng số nguyên kết hợp Parameterized Query. |

## Hướng dẫn sử dụng

Sử dụng giao diện dòng lệnh thông qua module `src.cli`:

```bash
python -m src.cli --help
```

### Kiểm tra kết nối và đo thông số cơ sở (`probe`)

Lệnh `probe` gửi yêu cầu HTTP ban đầu tới mục tiêu để thu thập trạng thái phản hồi, độ dài nội dung và độ trễ mạng:

```bash
python -m src.cli probe --url "http://127.0.0.1:5000/vuln/error/products?category=books" --timeout 10
```

Các tùy chọn:
- `-u`, `--url` (Bắt buộc): Địa chỉ URL mục tiêu cần kiểm tra.
- `-t`, `--timeout` (Mặc định: `10.0`): Thời gian chờ phản hồi tối đa tính bằng giây.

## Lưu ý pháp lý và Bảo mật

Công cụ và môi trường thực nghiệm trong dự án này được xây dựng thuần túy cho mục đích nghiên cứu, học tập và kiểm thử bảo mật trên hệ thống cục bộ hoặc hệ thống đã được cấp phép rõ ràng bằng văn bản. Không sử dụng công cụ trên các hệ thống khi chưa có sự đồng ý của chủ sở hữu.
