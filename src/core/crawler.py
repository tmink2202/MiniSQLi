from collections import deque
from dataclasses import dataclass, field
from typing import Deque, Dict, List, Optional, Set, Tuple
from urllib.parse import parse_qsl, urlencode, urljoin, urlsplit, urlunsplit

from bs4 import BeautifulSoup

from src.core.client import AuditHttpClient


@dataclass
class DiscoveredEndpoint:
    """Biểu diễn một endpoint (kèm tham số mẫu) thu thập được qua quá trình crawl."""
    url: str
    method: str = "GET"
    data: Optional[Dict[str, str]] = field(default=None)
    source_url: str = ""
    depth: int = 0


class WebCrawler:
    """
    Bộ thu thập Endpoint tự động trong cùng miền (Same-Origin Scope).
    Bóc tách các liên kết (<a href>) và biểu mẫu (<form>, <input>, <select>, <textarea>).
    """

    def __init__(
        self,
        client: AuditHttpClient,
        max_depth: int = 2,
        max_pages: int = 50,
    ):
        self.client = client
        self.max_depth = max_depth
        self.max_pages = max_pages

    @staticmethod
    def _normalize_url(url: str) -> str:
        """Chuẩn hóa URL, loại bỏ fragment (#)."""
        split = urlsplit(url)
        return urlunsplit((split.scheme, split.netloc, split.path or "/", split.query, ""))

    @staticmethod
    def _is_same_origin(base_url: str, candidate_url: str) -> bool:
        b = urlsplit(base_url)
        c = urlsplit(candidate_url)
        return (b.scheme, b.netloc) == (c.scheme, c.netloc)

    @staticmethod
    def _endpoint_signature(method: str, url: str, data: Optional[Dict[str, str]]) -> Tuple[str, str, Tuple[str, ...]]:
        """Tạo chữ ký duy nhất theo (Method, BasePath, Tên_các_tham_số) để chống trùng lặp."""
        split = urlsplit(url)
        base_path = urlunsplit((split.scheme, split.netloc, split.path or "/", "", ""))
        query_keys = [k for k, _ in parse_qsl(split.query, keep_blank_values=True)]
        form_keys = list(data.keys()) if data else []
        all_keys = tuple(sorted(set(query_keys + form_keys)))
        return (method.upper(), base_path, all_keys)

    def crawl(self, start_url: str) -> List[DiscoveredEndpoint]:
        """Thực hiện thu thập các endpoint bắt đầu từ start_url theo thuật toán BFS."""
        normalized_start = self._normalize_url(start_url)
        queue: Deque[Tuple[str, int]] = deque([(normalized_start, 0)])
        visited_pages: Set[str] = set()
        seen_signatures: Set[Tuple[str, str, Tuple[str, ...]]] = set()
        discovered: List[DiscoveredEndpoint] = []

        # Nếu URL khởi đầu đã chứa query string, ghi nhận ngay làm một endpoint
        start_split = urlsplit(normalized_start)
        if start_split.query:
            sig = self._endpoint_signature("GET", normalized_start, None)
            seen_signatures.add(sig)
            discovered.append(
                DiscoveredEndpoint(
                    url=normalized_start,
                    method="GET",
                    data=None,
                    source_url=normalized_start,
                    depth=0,
                )
            )

        while queue and len(visited_pages) < self.max_pages:
            current_url, depth = queue.popleft()
            if current_url in visited_pages:
                continue
            visited_pages.add(current_url)

            response = self.client.send_request("GET", current_url)
            if response.error or response.status_code == 0 or not response.text:
                continue

            soup = BeautifulSoup(response.text, "html.parser")

            # 1. Thu thập các liên kết <a href="...">
            for a_tag in soup.find_all("a", href=True):
                raw_href = a_tag["href"].strip()
                if not raw_href or raw_href.startswith(("javascript:", "mailto:", "tel:")):
                    continue

                abs_url = self._normalize_url(urljoin(current_url, raw_href))
                if not self._is_same_origin(normalized_start, abs_url):
                    continue

                parsed_link = urlsplit(abs_url)
                if parsed_link.query:
                    sig = self._endpoint_signature("GET", abs_url, None)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        discovered.append(
                            DiscoveredEndpoint(
                                url=abs_url,
                                method="GET",
                                data=None,
                                source_url=current_url,
                                depth=depth + 1,
                            )
                        )

                if depth < self.max_depth and abs_url not in visited_pages:
                    queue.append((abs_url, depth + 1))

            # 2. Thu thập các biểu mẫu <form>
            for form_tag in soup.find_all("form"):
                action = form_tag.get("action") or current_url
                form_url = self._normalize_url(urljoin(current_url, str(action)))
                if not self._is_same_origin(normalized_start, form_url):
                    continue

                method = str(form_tag.get("method", "GET")).upper()
                if method not in ("GET", "POST"):
                    method = "GET"

                fields = self._extract_form_fields(form_tag)
                if not fields:
                    continue

                if method == "GET":
                    split_form = urlsplit(form_url)
                    existing_q = dict(parse_qsl(split_form.query, keep_blank_values=True))
                    existing_q.update(fields)
                    full_get_url = urlunsplit(
                        (split_form.scheme, split_form.netloc, split_form.path or "/", urlencode(existing_q), "")
                    )
                    sig = self._endpoint_signature("GET", full_get_url, None)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        discovered.append(
                            DiscoveredEndpoint(
                                url=full_get_url,
                                method="GET",
                                data=None,
                                source_url=current_url,
                                depth=depth + 1,
                            )
                        )
                else:
                    sig = self._endpoint_signature("POST", form_url, fields)
                    if sig not in seen_signatures:
                        seen_signatures.add(sig)
                        discovered.append(
                            DiscoveredEndpoint(
                                url=form_url,
                                method="POST",
                                data=fields,
                                source_url=current_url,
                                depth=depth + 1,
                            )
                        )

        return discovered

    @staticmethod
    def _extract_form_fields(form_tag) -> Dict[str, str]:
        """Trích xuất các trường input/select/textarea và giá trị mặc định trong thẻ <form>."""
        fields: Dict[str, str] = {}
        for control in form_tag.find_all(["input", "select", "textarea"]):
            name = control.get("name")
            if not name:
                continue
            input_type = str(control.get("type", "text")).lower()
            if input_type in ("submit", "button", "image", "reset", "file"):
                continue

            if control.name == "select":
                option = control.find("option", selected=True) or control.find("option")
                val = option.get("value", option.text.strip()) if option else "1"
            elif control.name == "textarea":
                val = control.text.strip() or "sample"
            else:
                val = control.get("value")
                if val is None or val == "":
                    val = "1" if input_type == "number" else "test"

            fields[str(name)] = str(val)
        return fields
