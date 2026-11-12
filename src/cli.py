from typing import Dict, List, Optional
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from src.core.baseline import BaselineEngine
from src.core.client import AuditHttpClient
from src.core.crawler import DiscoveredEndpoint, WebCrawler
from src.core.parser import ParameterParser

app = typer.Typer(help="Công cụ rà quét và đánh giá lỗ hổng SQL Injection phục vụ kiểm thử nội bộ.")
console = Console()


def _parse_raw_headers(raw_headers: Optional[List[str]]) -> Dict[str, str]:
    headers: Dict[str, str] = {}
    if not raw_headers:
        return headers
    for item in raw_headers:
        if ":" in item:
            k, v = item.split(":", 1)
            headers[k.strip()] = v.strip()
    return headers


@app.callback()
def main():
    """
    SQLi Audit Tool CLI - Khung dòng lệnh quản lý các tác vụ kiểm thử.
    """
    pass


@app.command()
def probe(
    url: str = typer.Option(..., "--url", "-u", help="URL mục tiêu cần kiểm tra kết nối"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Thời gian chờ tối đa (giây)"),
):
    """Kiểm tra kết nối HTTP ban đầu và đo thông số Baseline cơ bản."""
    client = AuditHttpClient(timeout=timeout)
    try:
        console.print(f"[bold cyan][*][/bold cyan] Đang kiểm tra kết nối tới: [underline]{url}[/underline]")
        res = client.send_request("GET", url)

        if res.error:
            console.print(f"[bold red][!] Lỗi kết nối:[/bold red] {res.error}")
            raise typer.Exit(code=1)

        table = Table(title="Thông số Phản hồi (Baseline Probe)")
        table.add_column("Thuộc tính", style="cyan")
        table.add_column("Giá trị", style="green")

        table.add_row("URL Thực tế", res.url)
        table.add_row("HTTP Status Code", str(res.status_code))
        table.add_row("Độ dài nội dung (Chars)", str(res.content_length))
        table.add_row("Thời gian phản hồi (ms)", f"{res.elapsed_ms} ms")

        console.print(table)
    finally:
        client.close()


@app.command()
def crawl(
    url: str = typer.Option(..., "--url", "-u", help="URL khởi đầu để thu thập các endpoint"),
    crawl_depth: int = typer.Option(2, "--crawl-depth", "-d", help="Độ sâu thu thập liên kết tối đa"),
    max_pages: int = typer.Option(50, "--max-pages", help="Số trang tối đa được phép duyệt"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Thời gian chờ tối đa (giây)"),
):
    """Tự động thu thập (crawl) danh sách các endpoint và biểu mẫu trong cùng miền (Same-Origin)."""
    client = AuditHttpClient(timeout=timeout)
    try:
        console.print(
            f"[bold cyan][*][/bold cyan] Bắt đầu thu thập endpoint từ: "
            f"[underline]{url}[/underline] (Độ sâu tối đa: {crawl_depth})"
        )
        crawler = WebCrawler(client=client, max_depth=crawl_depth, max_pages=max_pages)
        endpoints = crawler.crawl(url)

        if not endpoints:
            console.print("[yellow][!] Không tìm thấy endpoint nào có tham số đầu vào.[/yellow]")
            return

        table = Table(title=f"Danh sách Endpoint Thu thập được ({len(endpoints)} mục tiêu)")
        table.add_column("#", style="dim", justify="right")
        table.add_column("Method", style="bold magenta")
        table.add_column("URL Endpoint", style="cyan")
        table.add_column("Tham số (Query / Form)", style="green")
        table.add_column("Độ sâu", justify="center")

        for idx, ep in enumerate(endpoints, start=1):
            parsed = ParameterParser.parse(url=ep.url, method=ep.method, data=ep.data)
            params_str = ", ".join(f"{p.name}={p.original_value} ({p.location})" for p in parsed.injection_points)
            table.add_row(str(idx), ep.method, ep.url, params_str or "-", str(ep.depth))

        console.print(table)
    finally:
        client.close()


@app.command()
def analyze(
    url: str = typer.Option(..., "--url", "-u", help="URL mục tiêu hoặc trang khởi đầu"),
    method: str = typer.Option("GET", "--method", "-X", help="Phương thức HTTP (GET, POST)"),
    data: Optional[str] = typer.Option(None, "--data", "-d", help="Dữ liệu Form body (x-www-form-urlencoded)"),
    json_data: Optional[str] = typer.Option(None, "--json", "-j", help="Dữ liệu JSON body"),
    header: Optional[List[str]] = typer.Option(None, "--header", "-H", help="HTTP Header bổ sung (VD: 'Cookie: id=1')"),
    include_headers: bool = typer.Option(False, "--include-headers", help="Đưa các Header phổ biến vào danh sách kiểm thử"),
    samples: int = typer.Option(3, "--samples", "-s", help="Số lần gửi request để đo Baseline (2-3)"),
    enable_crawl: bool = typer.Option(False, "--crawl", "-c", help="Tự động thu thập toàn bộ endpoint từ URL trước khi phân tích"),
    crawl_depth: int = typer.Option(2, "--crawl-depth", help="Độ sâu crawl tối đa khi bật --crawl"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Thời gian chờ tối đa (giây)"),
):
    """
    Thực hiện quy trình Tuần 2: Thu thập Endpoint (tùy chọn) -> Bóc tách tham số -> Đo Baseline -> Kiểm tra Heuristic.
    """
    client = AuditHttpClient(timeout=timeout)
    custom_headers = _parse_raw_headers(header)

    try:
        targets: List[DiscoveredEndpoint] = []
        if enable_crawl:
            console.print(f"[bold cyan][*][/bold cyan] Đang tự động thu thập các endpoint từ: [underline]{url}[/underline]")
            crawler = WebCrawler(client=client, max_depth=crawl_depth)
            targets = crawler.crawl(url)
            console.print(f"[bold green][+][/bold green] Đã tìm thấy [bold]{len(targets)}[/bold] endpoint có tham số.")

        if not targets:
            targets = [DiscoveredEndpoint(url=url, method=method.upper(), data=None, source_url=url, depth=0)]

        for idx, target in enumerate(targets, start=1):
            console.print(
                Panel(
                    f"[bold]Mục tiêu #{idx}:[/bold] [{target.method}] {target.url}",
                    border_style="cyan",
                )
            )
            parsed = ParameterParser.parse(
                url=target.url,
                method=target.method,
                data=target.data if target.data is not None else data,
                json_data=json_data,
                headers=custom_headers,
                include_headers=include_headers,
            )

            if not parsed.injection_points:
                console.print("[yellow][!] Không có tham số đầu vào nào để kiểm thử trên endpoint này.[/yellow]\n")
                continue

            # 1. Hiển thị các điểm đầu vào bóc tách được
            param_table = Table(title="1. Các Điểm Đầu vào Bóc tách được (Parameter Parser)")
            param_table.add_column("Vị trí (Location)", style="magenta")
            param_table.add_column("Tên Tham số", style="cyan")
            param_table.add_column("Giá trị Gốc", style="green")
            for pt in parsed.injection_points:
                param_table.add_row(pt.location, pt.name, pt.original_value)
            console.print(param_table)

            # 2. Ghi nhận Baseline
            baseline = BaselineEngine.record_baseline(client, parsed, num_samples=samples)
            base_table = Table(title=f"2. Hồ sơ Phản hồi Chuẩn (Baseline - {baseline.num_samples} mẫu)")
            base_table.add_column("Thông số", style="cyan")
            base_table.add_column("Giá trị Đo lường", style="green")
            base_table.add_row(
                "HTTP Status Code",
                f"{baseline.status_code} ({'Ổn định' if baseline.is_stable_status else 'Dao động'})",
            )
            base_table.add_row(
                "Độ dài phản hồi (avg / min..max)",
                f"{baseline.avg_length} chars ({baseline.min_length}..{baseline.max_length})",
            )
            base_table.add_row(
                "Thời gian phản hồi (avg ± stdev)",
                f"{baseline.avg_elapsed_ms} ms ± {baseline.stdev_elapsed_ms} ms",
            )
            sig_preview = ", ".join(baseline.dom_signature[:6])
            if len(baseline.dom_signature) > 6:
                sig_preview += f", ... (+{len(baseline.dom_signature) - 6} mục)"
            base_table.add_row("Cấu trúc DOM/JSON", sig_preview)
            console.print(base_table)

            # 3. Chạy kiểm tra Heuristic
            findings = BaselineEngine.run_heuristic_check(client, parsed, baseline)
            heur_table = Table(title="3. Kết quả Kiểm tra Heuristic (Ký tự đóng/mở chuỗi)")
            heur_table.add_column("Tham số", style="cyan")
            heur_table.add_column("Ký tự thử", justify="center", style="bold yellow")
            heur_table.add_column("Status (Base -> Probe)", justify="center")
            heur_table.add_column("Độ dài (Base -> Probe)", justify="right")
            heur_table.add_column("Đánh giá", justify="center")
            heur_table.add_column("Chi tiết nhận định")

            suspicious_params = set()
            for f in findings:
                status_badge = (
                    "[bold red]NGHI NGỜ (SUSPICIOUS)[/bold red]"
                    if f.is_suspicious
                    else "[bold green]AN TOÀN (SAFE)[/bold green]"
                )
                if f.is_suspicious:
                    suspicious_params.add(f"{f.point.name} ({f.point.location})")
                heur_table.add_row(
                    f"{f.point.name} ({f.point.location})",
                    f.delimiter,
                    f"{f.baseline_status} -> {f.probe_status}",
                    f"{f.baseline_avg_length} -> {f.probe_length}",
                    status_badge,
                    f.reason,
                )
            console.print(heur_table)

            if suspicious_params:
                console.print(
                    f"[bold red][!] Kết luận Heuristic:[/bold red] Phát hiện dấu hiệu bất thường tại tham số: "
                    f"[bold yellow]{', '.join(sorted(suspicious_params))}[/bold yellow] -> Cần chuyển sang quét chuyên sâu (Tuần 3-6).\n"
                )
            else:
                console.print(
                    "[bold green][✓] Kết luận Heuristic:[/bold green] Không phát hiện dấu hiệu bất thường trên các tham số.\n"
                )
    finally:
        client.close()


if __name__ == "__main__":
    app()
