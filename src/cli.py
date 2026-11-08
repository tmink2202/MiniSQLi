import typer
from rich.console import Console
from rich.table import Table
from src.core.client import AuditHttpClient

app = typer.Typer(help="Công cụ rà quét và đánh giá lỗ hổng SQL Injection phục vụ kiểm thử nội bộ.")
console = Console()

@app.callback()
def main():
    """
    SQLi Audit Tool CLI - Khung dòng lệnh quản lý các tác vụ kiểm thử.
    """
    pass

@app.command()
def probe(
    url: str = typer.Option(..., "--url", "-u", help="URL mục tiêu cần kiểm tra kết nối"),
    timeout: float = typer.Option(10.0, "--timeout", "-t", help="Thời gian chờ tối đa (giây)")
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

if __name__ == "__main__":
    app()