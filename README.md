# SQLi Audit Tool

Công cụ dòng lệnh (CLI) phục vụ rà quét, đo lường và phát hiện lỗ hổng SQL Injection (SQLi) trên các ứng dụng web trong môi trường kiểm thử nội bộ. Công cụ tập trung vào việc nhận diện điểm yếu bảo mật (Detection) và cung cấp khuyến nghị khắc phục (Remediation) thay vì khai thác trích xuất dữ liệu. Dự án đi kèm một môi trường thực nghiệm (Testbed) sử dụng Flask và PostgreSQL để đối chứng độ chính xác giữa các điểm giao tiếp có lỗ hổng (Vulnerable) và an toàn (Safe).

## Mục đích

- Chuẩn hóa quy trình phân tích điểm đầu vào (Query, Form, JSON, Header) và thu thập thông số phản hồi cơ sở (Baseline HTTP probing) trước khi kiểm thử.
- Cung cấp kiến trúc tách biệt giữa tầng giao tiếp mạng và phân tích (`core`), các bộ phát hiện lỗ hổng (`detectors`), cơ sở dữ liệu dấu hiệu nhận diện (`signatures`) và xuất báo cáo kèm hướng dẫn vá lỗi (`reporting`).
- Thiết lập môi trường kiểm thử cục bộ có kiểm soát nhằm đánh giá tỷ lệ phát hiện đúng (True Positive) và kiểm soát cảnh báo giả (False Positive) đối với 4 kỹ thuật SQLi điển hình:
  - **Error-based SQLi**: Nhận diện qua thông báo lỗi cú pháp và định danh hệ quản trị cơ sở dữ liệu (DBMS Fingerprinting).
  - **UNION-based SQLi**: Xác định cấu trúc cột và khả năng ghép nối kết quả truy vấn (In-band UNION) bằng các hằng số kiểm thử an toàn.
  - **Boolean-based Blind SQLi**: Nhận diện qua sự sai lệch nội dung hoặc cấu trúc DOM giữa điều kiện logic Đúng và Sai (Diffing Engine).
  - **Time-based Blind SQLi**: Nhận diện qua phân tích thống kê độ trễ thời gian phản hồi (`elapsed_ms`) có đối chiếu với độ lệch chuẩn của Baseline.

## Cấu trúc dự án

```text
.
├── requirements.txt        # Danh sách thư viện phụ thuộc
├── signatures/             # Mẫu nhận diện lỗi DBMS (Regex signatures)
├── src/
│   ├── cli.py              # Giao diện dòng lệnh chính (Typer)
│   ├── core/
│   │   ├── client.py       # HTTP client chuẩn hóa đo lường phản hồi (httpx)
│   │   ├── crawler.py      # Bộ thu thập tự động Endpoint & Form (BeautifulSoup4)
│   │   ├── parser.py       # Bộ bóc tách tham số (Query, Form, JSON, Cookie, Header)
│   │   └── baseline.py     # Đo lường Baseline (2-3 mẫu) và kiểm tra Heuristic
│   ├── detectors/          # Các module kiểm thử Error, UNION, Boolean, Time-based
│   └── reporting/          # Module tổng hợp kết quả và khuyến nghị khắc phục
├── testbed/
│   ├── app.py              # Ứng dụng Flask mô phỏng các endpoint Vulnerable và Safe
│   └── setup_db.sql        # Kịch bản khởi tạo cơ sở dữ liệu PostgreSQL tối thiểu quyền
└── tests/                  # Unit tests và integration tests (pytest)
    └── test_week2.py       # Kiểm thử tự động cho Crawler, Parser, Baseline & Heuristic
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

### Tự động thu thập Endpoint (`crawl`)

Thu thập toàn bộ liên kết (`<a href>`) và biểu mẫu (`<form>`) có tham số trong cùng miền (Same-Origin):

```bash
python -m src.cli crawl --url "http://127.0.0.1:5000/" --crawl-depth 2
```

### Phân tích tham số, đo Baseline và kiểm tra Heuristic (`analyze`)

Phân tích một URL cụ thể hoặc kết hợp `--crawl` để tự động thu thập mọi endpoint, bóc tách tham số, đo thông số chuẩn (Baseline) và thử nghiệm các ký tự đóng/mở chuỗi cơ bản:

```bash
# Phân tích một endpoint đơn lẻ
python -m src.cli analyze --url "http://127.0.0.1:5000/vuln/error/products?category=books"

# Tự động crawl toàn bộ trang đích và chạy phân tích Heuristic trên từng endpoint
python -m src.cli analyze --url "http://127.0.0.1:5000/" --crawl
```

## Lưu ý pháp lý và Bảo mật

Công cụ và môi trường thực nghiệm trong dự án này được xây dựng thuần túy cho mục đích nghiên cứu, học tập và kiểm thử bảo mật trên hệ thống cục bộ hoặc hệ thống đã được cấp phép rõ ràng bằng văn bản. Không sử dụng công cụ trên các hệ thống khi chưa có sự đồng ý của chủ sở hữu.
