import time
from dataclasses import dataclass
from typing import Dict, Optional, Any
import httpx

@dataclass
class HttpResponseData:
    url: str
    status_code: int
    text: str
    headers: Dict[str, str]
    elapsed_ms: float
    content_length: int
    error: Optional[str] = None

class AuditHttpClient:
    def __init__(self, timeout: float = 10.0, user_agent: str = "SQLiAuditTool/0.1 (LocalTesting)"):
        self.timeout = timeout
        self.client = httpx.Client(
            timeout=httpx.Timeout(timeout),
            headers={"User-Agent": user_agent},
            follow_redirects=True
        )

    def send_request(
        self,
        method: str,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None
    ) -> HttpResponseData:
        """Gửi HTTP request và chuẩn hóa dữ liệu đo lường trả về."""
        start_time = time.perf_counter()
        try:
            response = self.client.request(
                method=method.upper(),
                url=url,
                params=params,
                data=data,
                json=json_data,
                headers=headers
            )
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HttpResponseData(
                url=str(response.url),
                status_code=response.status_code,
                text=response.text,
                headers=dict(response.headers),
                elapsed_ms=round(elapsed_ms, 2),
                content_length=len(response.text)
            )
        except httpx.RequestError as exc:
            elapsed_ms = (time.perf_counter() - start_time) * 1000.0
            return HttpResponseData(
                url=url,
                status_code=0,
                text="",
                headers={},
                elapsed_ms=round(elapsed_ms, 2),
                content_length=0,
                error=str(exc)
            )

    def close(self):
        self.client.close()