import json
from typing import Any, Dict, Optional

from src.core.baseline import BaselineEngine
from src.core.client import AuditHttpClient, HttpResponseData
from src.core.crawler import WebCrawler
from src.core.parser import InjectionPoint, ParameterParser


class MockAuditHttpClient(AuditHttpClient):
    """HTTP Client giả lập phục vụ kiểm thử đơn vị (Unit Test) không cần kết nối mạng."""

    def __init__(self):
        self.timeout = 5.0
        self.client = None

    def send_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> HttpResponseData:
        # 1. Trang chủ chứa link và form phục vụ Crawler
        if url == "http://127.0.0.1:5000/":
            html = """
            <html>
                <body>
                    <a href="/vuln/error/products?category=books">Error Endpoint</a>
                    <a href="/vuln/blind/article?id=1">Blind Endpoint</a>
                    <a href="/safe/products?category=books">Safe Products</a>
                    <a href="/safe/article?id=1">Safe Article</a>
                    <a href="https://external.example.com/page?id=99">External Link</a>
                    <form action="/login" method="POST">
                        <input type="text" name="username" value="admin" />
                        <input type="password" name="password" value="secret" />
                        <input type="submit" value="Login" />
                    </form>
                </body>
            </html>
            """
            return HttpResponseData(
                url=url,
                status_code=200,
                text=html,
                headers={"content-type": "text/html"},
                elapsed_ms=5.0,
                content_length=len(html),
            )

        # 2. Endpoint lỗi Error-based: nối chuỗi gây lỗi 500 khi có ký tự đóng chuỗi
        if url.startswith("http://127.0.0.1:5000/vuln/error/products"):
            if "%27" in url or "'" in url:
                body = json.dumps({"status": "error", "db_error": "unterminated quoted string"})
                return HttpResponseData(url, 500, body, {}, 6.0, len(body))
            if "category=books" in url and not url.endswith("books"):
                # Các giá trị tìm kiếm không khớp trong DB trả về danh sách rỗng
                body = json.dumps({"status": "ok", "count": 0, "data": []})
                return HttpResponseData(url, 200, body, {}, 4.5, len(body))
            body = json.dumps({"status": "ok", "count": 2, "data": [[1, "Book A", 10.0]]})
            return HttpResponseData(url, 200, body, {}, 4.8, len(body))

        # 3. Endpoint lỗi Blind: trả về 404 khi cú pháp SQL bị phá vỡ
        if url.startswith("http://127.0.0.1:5000/vuln/blind/article"):
            if "id=1" in url and url.endswith("id=1"):
                body = json.dumps({"status": "ok", "found": True, "article": "Security 101"})
                return HttpResponseData(url, 200, body, {}, 5.1, len(body))
            body = json.dumps({"status": "ok", "found": False})
            return HttpResponseData(url, 404, body, {}, 5.2, len(body))

        # 4. Endpoint an toàn dùng Parameterized Query (/safe/products)
        if url.startswith("http://127.0.0.1:5000/safe/products"):
            if url.endswith("category=books"):
                body = json.dumps({"status": "ok", "count": 2, "data": [[1, "Book A", 10.0]]})
                return HttpResponseData(url, 200, body, {}, 4.2, len(body))
            body = json.dumps({"status": "ok", "count": 0, "data": []})
            return HttpResponseData(url, 200, body, {}, 4.1, len(body))

        # 5. Endpoint an toàn kiểm tra kiểu dữ liệu số nguyên (/safe/article)
        if url.startswith("http://127.0.0.1:5000/safe/article"):
            query_val = url.split("id=", 1)[-1] if "id=" in url else ""
            if not query_val.isdigit():
                body = json.dumps({"status": "bad_request", "message": "Invalid ID format"})
                return HttpResponseData(url, 400, body, {}, 2.0, len(body))
            body = json.dumps({"status": "ok", "found": True})
            return HttpResponseData(url, 200, body, {}, 4.0, len(body))

        return HttpResponseData(url, 200, "<html></html>", {}, 3.0, 13)

    def close(self):
        pass


def test_parameter_parser_all_locations():
    parsed = ParameterParser.parse(
        url="http://127.0.0.1:5000/search?category=books&sort=asc",
        method="POST",
        data="filter=active",
        json_data={"page": 1},
        headers={"Cookie": "session_id=xyz123; theme=dark", "User-Agent": "CustomAgent/1.0"},
        include_headers=True,
    )

    assert parsed.base_url == "http://127.0.0.1:5000/search"
    assert parsed.query_params == {"category": "books", "sort": "asc"}
    assert parsed.form_data == {"filter": "active"}
    assert parsed.json_data == {"page": 1}
    assert parsed.cookies == {"session_id": "xyz123", "theme": "dark"}

    locations = {(p.location, p.name, p.original_value) for p in parsed.injection_points}
    assert ("query", "category", "books") in locations
    assert ("query", "sort", "asc") in locations
    assert ("form", "filter", "active") in locations
    assert ("json", "page", "1") in locations
    assert ("cookie", "session_id", "xyz123") in locations
    assert ("header", "User-Agent", "CustomAgent/1.0") in locations

    target_point = InjectionPoint(location="query", name="category", original_value="books")
    kwargs = ParameterParser.build_request_kwargs(parsed, point=target_point, test_value="'", append=True)
    assert "category=books%27" in kwargs["url"]


def test_web_crawler_same_origin_and_forms():
    client = MockAuditHttpClient()
    crawler = WebCrawler(client=client, max_depth=1)
    endpoints = crawler.crawl("http://127.0.0.1:5000/")

    urls_and_methods = {(ep.method, ep.url) for ep in endpoints}
    assert ("GET", "http://127.0.0.1:5000/vuln/error/products?category=books") in urls_and_methods
    assert ("GET", "http://127.0.0.1:5000/vuln/blind/article?id=1") in urls_and_methods
    assert ("GET", "http://127.0.0.1:5000/safe/products?category=books") in urls_and_methods
    assert ("GET", "http://127.0.0.1:5000/safe/article?id=1") in urls_and_methods
    assert ("POST", "http://127.0.0.1:5000/login") in urls_and_methods

    # Đảm bảo không thu thập tên miền ngoài (external.example.com)
    assert all("external.example.com" not in ep.url for ep in endpoints)


def test_baseline_and_heuristic_true_and_false_positives():
    client = MockAuditHttpClient()

    # 1. Vulnerable Error-based -> Phải cảnh báo (is_suspicious = True)
    parsed_vuln_err = ParameterParser.parse("http://127.0.0.1:5000/vuln/error/products?category=books")
    base_vuln_err = BaselineEngine.record_baseline(client, parsed_vuln_err, num_samples=3)
    assert base_vuln_err.status_code == 200
    assert base_vuln_err.is_stable_status is True
    findings_err = BaselineEngine.run_heuristic_check(client, parsed_vuln_err, base_vuln_err)
    assert any(f.is_suspicious and f.probe_status == 500 for f in findings_err)

    # 2. Vulnerable Blind -> Phải cảnh báo sự thay đổi trạng thái 200 -> 404
    parsed_vuln_blind = ParameterParser.parse("http://127.0.0.1:5000/vuln/blind/article?id=1")
    base_vuln_blind = BaselineEngine.record_baseline(client, parsed_vuln_blind, num_samples=3)
    findings_blind = BaselineEngine.run_heuristic_check(client, parsed_vuln_blind, base_vuln_blind)
    assert any(f.is_suspicious and f.probe_status == 404 for f in findings_blind)

    # 3. Safe Parameterized Products -> KHÔNG ĐƯỢC cảnh báo giả (False Positive = 0)
    parsed_safe_prod = ParameterParser.parse("http://127.0.0.1:5000/safe/products?category=books")
    base_safe_prod = BaselineEngine.record_baseline(client, parsed_safe_prod, num_samples=3)
    findings_safe_prod = BaselineEngine.run_heuristic_check(client, parsed_safe_prod, base_safe_prod)
    assert all(not f.is_suspicious for f in findings_safe_prod)

    # 4. Safe Validated Article (HTTP 400) -> KHÔNG ĐƯỢC cảnh báo giả
    parsed_safe_art = ParameterParser.parse("http://127.0.0.1:5000/safe/article?id=1")
    base_safe_art = BaselineEngine.record_baseline(client, parsed_safe_art, num_samples=3)
    findings_safe_art = BaselineEngine.run_heuristic_check(client, parsed_safe_art, base_safe_art)
    assert all(not f.is_suspicious for f in findings_safe_art)
