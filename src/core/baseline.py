import json
import statistics
from dataclasses import dataclass, field
from typing import Any, List, Tuple

from bs4 import BeautifulSoup

from src.core.client import AuditHttpClient, HttpResponseData
from src.core.parser import InjectionPoint, ParameterParser, ParsedRequest


@dataclass
class BaselineProfile:
    """Hồ sơ phản hồi chuẩn (Baseline) của một Endpoint trước khi kiểm thử."""
    url: str
    method: str
    num_samples: int
    status_code: int
    is_stable_status: bool
    avg_length: float
    min_length: int
    max_length: int
    avg_elapsed_ms: float
    stdev_elapsed_ms: float
    dom_signature: Tuple[str, ...]
    sample_texts: List[str] = field(default_factory=list)


@dataclass
class HeuristicFinding:
    """Kết quả kiểm tra Heuristic trên một điểm đầu vào với một ký tự thử nghiệm."""
    point: InjectionPoint
    delimiter: str
    baseline_status: int
    probe_status: int
    baseline_avg_length: float
    probe_length: int
    dom_changed: bool
    is_suspicious: bool
    reason: str


class BaselineEngine:
    """
    Thực hiện đo lường Baseline (2-3 request chuẩn) và kiểm tra Heuristic ban đầu
    bằng các ký tự đóng/mở chuỗi cơ bản (' , \" , ) , ;).
    """

    DEFAULT_DELIMITERS: Tuple[str, ...] = ("'", '"', ")", ";")

    @staticmethod
    def extract_structure_signature(text: str) -> Tuple[str, ...]:
        """
        Trích xuất cấu trúc đặc trưng của phản hồi:
        - Nếu là JSON: trích xuất danh sách các khóa (keys).
        - Nếu là HTML/Văn bản: trích xuất thứ tự các thẻ HTML trong DOM.
        """
        stripped = text.strip()
        if stripped.startswith(("{", "[")):
            try:
                data = json.loads(stripped)
                return BaselineEngine._extract_json_keys(data)
            except json.JSONDecodeError:
                pass

        soup = BeautifulSoup(text, "html.parser")
        tags = tuple(tag.name for tag in soup.find_all(True))
        if tags:
            return tags
        return ("plain_text",) if stripped else ("empty",)

    @staticmethod
    def _extract_json_keys(obj: Any, prefix: str = "") -> Tuple[str, ...]:
        keys: List[str] = []
        if isinstance(obj, dict):
            for k in sorted(obj.keys()):
                full_key = f"{prefix}.{k}" if prefix else str(k)
                keys.append(f"json:{full_key}")
                keys.extend(BaselineEngine._extract_json_keys(obj[k], full_key))
        elif isinstance(obj, list) and obj:
            keys.extend(BaselineEngine._extract_json_keys(obj[0], f"{prefix}[]"))
        return tuple(keys)

    @classmethod
    def record_baseline(
        cls,
        client: AuditHttpClient,
        parsed: ParsedRequest,
        num_samples: int = 3,
    ) -> BaselineProfile:
        """
        Gửi num_samples (mặc định 3) request bình thường tới mục tiêu để ghi nhận
        mã trạng thái HTTP, độ dài phản hồi, cấu trúc DOM/JSON và thời gian phản hồi trung bình.
        """
        if num_samples < 1:
            num_samples = 1

        req_kwargs = ParameterParser.build_request_kwargs(parsed)
        responses: List[HttpResponseData] = []
        for _ in range(num_samples):
            res = client.send_request(**req_kwargs)
            responses.append(res)

        statuses = [r.status_code for r in responses]
        lengths = [r.content_length for r in responses]
        times = [r.elapsed_ms for r in responses]
        texts = [r.text for r in responses]

        primary_status = statuses[0]
        is_stable = len(set(statuses)) == 1
        avg_len = round(statistics.mean(lengths), 2)
        avg_time = round(statistics.mean(times), 2)
        stdev_time = round(statistics.stdev(times), 2) if len(times) > 1 else 0.0
        dom_sig = cls.extract_structure_signature(texts[0])

        return BaselineProfile(
            url=parsed.full_url,
            method=parsed.method,
            num_samples=num_samples,
            status_code=primary_status,
            is_stable_status=is_stable,
            avg_length=avg_len,
            min_length=min(lengths),
            max_length=max(lengths),
            avg_elapsed_ms=avg_time,
            stdev_elapsed_ms=stdev_time,
            dom_signature=dom_sig,
            sample_texts=texts,
        )

    @classmethod
    def run_heuristic_check(
        cls,
        client: AuditHttpClient,
        parsed: ParsedRequest,
        baseline: BaselineProfile,
        delimiters: Tuple[str, ...] = DEFAULT_DELIMITERS,
    ) -> List[HeuristicFinding]:
        """
        Thử nghiệm các ký tự đóng/mở chuỗi cơ bản trên từng tham số đầu vào
        và đối chiếu với Baseline cùng mẫu đối chứng (Benign Control) để phát hiện bất thường.
        """
        findings: List[HeuristicFinding] = []
        baseline_spread = max(10, baseline.max_length - baseline.min_length)

        for point in parsed.injection_points:
            # Gửi 1 request đối chứng vô hại (chỉ nối thêm chuỗi chữ/số thông thường)
            ctrl_kwargs = ParameterParser.build_request_kwargs(
                parsed, point=point, test_value="ctrl9", append=True
            )
            ctrl_res = client.send_request(**ctrl_kwargs)
            ctrl_sig = cls.extract_structure_signature(ctrl_res.text)

            for delim in delimiters:
                probe_kwargs = ParameterParser.build_request_kwargs(
                    parsed, point=point, test_value=delim, append=True
                )
                probe_res = client.send_request(**probe_kwargs)
                probe_sig = cls.extract_structure_signature(probe_res.text)

                dom_changed = probe_sig != baseline.dom_signature
                is_suspicious = False
                reason = "Phản hồi ổn định, không phát hiện dấu hiệu bất thường."

                if probe_res.error:
                    is_suspicious = True
                    reason = f"Lỗi kết nối/phản hồi khi chèn '{delim}': {probe_res.error}"
                elif probe_res.status_code >= 500 and baseline.status_code < 500:
                    is_suspicious = True
                    reason = (
                        f"Máy chủ trả về lỗi HTTP {probe_res.status_code} "
                        f"(Baseline: {baseline.status_code}) khi thử ký tự '{delim}'."
                    )
                elif probe_res.status_code in (400, 422) and baseline.status_code == 200:
                    is_suspicious = False
                    reason = (
                        f"Đầu vào bị từ chối bởi bộ kiểm tra hợp lệ "
                        f"(HTTP {probe_res.status_code} Bad Request)."
                    )
                elif probe_res.status_code != baseline.status_code:
                    is_suspicious = True
                    reason = (
                        f"Thay đổi mã trạng thái HTTP bất thường: "
                        f"{baseline.status_code} -> {probe_res.status_code} khi thử '{delim}'."
                    )
                else:
                    # Cùng mã trạng thái HTTP (ví dụ 200): đối chiếu với cả Baseline và Benign Control
                    differs_from_ctrl = (
                        probe_res.status_code != ctrl_res.status_code
                        or probe_sig != ctrl_sig
                        or abs(probe_res.content_length - ctrl_res.content_length) > baseline_spread
                    )
                    length_delta_baseline = abs(probe_res.content_length - baseline.avg_length)

                    if dom_changed and probe_sig != ctrl_sig:
                        is_suspicious = True
                        reason = f"Cấu trúc DOM/JSON thay đổi bất thường khi thử ký tự '{delim}'."
                    elif differs_from_ctrl and length_delta_baseline > baseline_spread:
                        is_suspicious = True
                        reason = (
                            f"Độ dài phản hồi lệch chuẩn ({probe_res.content_length} chars "
                            f"so với Baseline {baseline.avg_length} chars và Control {ctrl_res.content_length} chars)."
                        )

                findings.append(
                    HeuristicFinding(
                        point=point,
                        delimiter=delim,
                        baseline_status=baseline.status_code,
                        probe_status=probe_res.status_code,
                        baseline_avg_length=baseline.avg_length,
                        probe_length=probe_res.content_length,
                        dom_changed=dom_changed,
                        is_suspicious=is_suspicious,
                        reason=reason,
                    )
                )

        return findings
