import copy
import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


@dataclass(frozen=True)
class InjectionPoint:
    """Biểu diễn một vị trí tham số đầu vào có thể kiểm thử."""
    location: str  # "query" | "form" | "json" | "header" | "cookie"
    name: str
    original_value: str


@dataclass
class ParsedRequest:
    """Cấu trúc lưu trữ thông tin HTTP request sau khi đã phân tách tham số."""
    method: str
    base_url: str
    full_url: str
    query_params: Dict[str, str] = field(default_factory=dict)
    form_data: Dict[str, str] = field(default_factory=dict)
    json_data: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    cookies: Dict[str, str] = field(default_factory=dict)
    injection_points: List[InjectionPoint] = field(default_factory=list)


class ParameterParser:
    """
    Bộ phân tích tham số đầu vào từ URL Query String (GET),
    Form Body (x-www-form-urlencoded), JSON Body (POST),
    Cookie và các HTTP Header phổ biến.
    """

    AUDITABLE_HEADERS = ("User-Agent", "Referer", "X-Forwarded-For")

    @classmethod
    def parse(
        cls,
        url: str,
        method: str = "GET",
        data: Optional[Union[str, Dict[str, Any]]] = None,
        json_data: Optional[Union[str, Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
        include_headers: bool = False,
    ) -> ParsedRequest:
        """Bóc tách toàn bộ các điểm đầu vào từ thông tin HTTP request."""
        split_url = urlsplit(url)
        base_url = urlunsplit((split_url.scheme, split_url.netloc, split_url.path, "", ""))

        query_params: Dict[str, str] = {}
        for k, v in parse_qsl(split_url.query, keep_blank_values=True):
            query_params[k] = v

        parsed_form: Dict[str, str] = {}
        if data:
            if isinstance(data, str):
                for k, v in parse_qsl(data, keep_blank_values=True):
                    parsed_form[k] = v
            elif isinstance(data, dict):
                parsed_form = {str(k): str(v) for k, v in data.items()}

        parsed_json: Dict[str, Any] = {}
        if json_data:
            if isinstance(json_data, str):
                loaded = json.loads(json_data)
                if isinstance(loaded, dict):
                    parsed_json = loaded
            elif isinstance(json_data, dict):
                parsed_json = copy.deepcopy(json_data)

        clean_headers: Dict[str, str] = {}
        cookies: Dict[str, str] = {}
        if headers:
            for h_key, h_val in headers.items():
                if h_key.lower() == "cookie":
                    cookies.update(cls._parse_cookie_string(h_val))
                else:
                    clean_headers[h_key] = h_val

        injection_points: List[InjectionPoint] = []

        for k, v in query_params.items():
            injection_points.append(InjectionPoint(location="query", name=k, original_value=v))

        for k, v in parsed_form.items():
            injection_points.append(InjectionPoint(location="form", name=k, original_value=v))

        for k, v in parsed_json.items():
            if isinstance(v, (str, int, float, bool)) or v is None:
                val_str = "" if v is None else str(v)
                injection_points.append(InjectionPoint(location="json", name=k, original_value=val_str))

        for k, v in cookies.items():
            injection_points.append(InjectionPoint(location="cookie", name=k, original_value=v))

        if include_headers:
            for h_name in cls.AUDITABLE_HEADERS:
                # Tìm header không phân biệt hoa thường hoặc tạo mặc định nếu có yêu cầu quét header
                matched_key = next((k for k in clean_headers if k.lower() == h_name.lower()), None)
                if matched_key:
                    injection_points.append(
                        InjectionPoint(
                            location="header",
                            name=matched_key,
                            original_value=clean_headers[matched_key],
                        )
                    )

        return ParsedRequest(
            method=method.upper(),
            base_url=base_url,
            full_url=url,
            query_params=query_params,
            form_data=parsed_form,
            json_data=parsed_json,
            headers=clean_headers,
            cookies=cookies,
            injection_points=injection_points,
        )

    @staticmethod
    def _parse_cookie_string(cookie_str: str) -> Dict[str, str]:
        cookies: Dict[str, str] = {}
        for part in cookie_str.split(";"):
            part = part.strip()
            if not part:
                continue
            if "=" in part:
                k, v = part.split("=", 1)
                cookies[k.strip()] = v.strip()
        return cookies

    @staticmethod
    def _serialize_cookies(cookies: Dict[str, str]) -> str:
        return "; ".join(f"{k}={v}" for k, v in cookies.items())

    @classmethod
    def build_request_kwargs(
        cls,
        parsed: ParsedRequest,
        point: Optional[InjectionPoint] = None,
        test_value: str = "",
        append: bool = True,
    ) -> Dict[str, Any]:
        """
        Tạo bộ tham số chuẩn cho AuditHttpClient.send_request().
        Nếu point=None, trả về bộ tham số gốc (phục vụ đo Baseline).
        Nếu có point, chèn nối tiếp (append=True) hoặc thay thế (append=False) giá trị tại điểm đó.
        """
        query = dict(parsed.query_params)
        form = dict(parsed.form_data)
        js = copy.deepcopy(parsed.json_data)
        hdrs = dict(parsed.headers)
        cks = dict(parsed.cookies)

        if point is not None:
            new_val = f"{point.original_value}{test_value}" if append else test_value
            if point.location == "query" and point.name in query:
                query[point.name] = new_val
            elif point.location == "form" and point.name in form:
                form[point.name] = new_val
            elif point.location == "json" and point.name in js:
                js[point.name] = new_val
            elif point.location == "cookie" and point.name in cks:
                cks[point.name] = new_val
            elif point.location == "header":
                hdrs[point.name] = new_val

        if cks:
            hdrs["Cookie"] = cls._serialize_cookies(cks)

        url = parsed.base_url
        if query:
            url = f"{parsed.base_url}?{urlencode(query)}"

        return {
            "method": parsed.method,
            "url": url,
            "params": None,  # Đã được mã hóa trực tiếp vào URL để kiểm soát chính xác chuỗi query
            "data": form if form else None,
            "json_data": js if js else None,
            "headers": hdrs if hdrs else None,
        }
