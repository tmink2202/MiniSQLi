import psycopg
from flask import Flask, request, jsonify

app = Flask(__name__)

DB_DSN = "dbname=sqli_testbed_db user=testbed_user password=local_test_pass_123 host=127.0.0.1 port=5432"

def get_db_conn():
    # autocommit=True giúp tránh lỗi kẹt transaction (InFailedSqlTransaction) khi test
    return psycopg.connect(DB_DSN, autocommit=True)

# ==========================================
# NHÓM 1: ENDPOINT MÔ PHỎNG LỖI (VULNERABLE)
# ==========================================

@app.route("/vuln/error/products")
def vuln_error_products():
    """Mô phỏng ngữ cảnh nối chuỗi trực tiếp và trả về chi tiết lỗi DBMS (HTTP 500)."""
    category = request.args.get("category", "books")
    query = f"SELECT id, name, price FROM products WHERE category = '{category}' AND is_published = TRUE"
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            return jsonify({"status": "ok", "count": len(rows), "data": rows}), 200
    except psycopg.Error as e:
        # Trả về thông báo lỗi của PostgreSQL để phục vụ kiểm thử module Error-based
        return jsonify({"status": "error", "db_error": str(e)}), 500

@app.route("/vuln/blind/article")
def vuln_blind_article():
    """Mô phỏng ngữ cảnh ẩn lỗi chi tiết: chỉ trả về Found / Not Found (phục vụ Boolean/Time-based)."""
    article_id = request.args.get("id", "1")
    query = f"SELECT id, title, author FROM articles WHERE id = {article_id}"
    try:
        with get_db_conn() as conn, conn.cursor() as cur:
            cur.execute(query)
            row = cur.fetchone()
            if row:
                return jsonify({"status": "ok", "found": True, "article": row[1]}), 200
            return jsonify({"status": "ok", "found": False}), 404
    except psycopg.Error:
        # Ẩn hoàn toàn lỗi SQL, chỉ trả về phản hồi chung
        return jsonify({"status": "ok", "found": False}), 404

# ==========================================
# NHÓM 2: ENDPOINT AN TOÀN ĐỐI CHỨNG (SAFE)
# ==========================================

@app.route("/safe/products")
def safe_products():
    """Sử dụng Parameterized Query: Công cụ quét KHÔNG ĐƯỢC báo lỗi tại đây."""
    category = request.args.get("category", "books")
    query = "SELECT id, name, price FROM products WHERE category = %s AND is_published = TRUE"
    with get_db_conn() as conn, conn.cursor() as cur:
        cur.execute(query, (category,))
        rows = cur.fetchall()
        return jsonify({"status": "ok", "count": len(rows), "data": rows}), 200

@app.route("/safe/article")
def safe_article():
    """Kiểm tra kiểu dữ liệu đầu vào kết hợp Parameterized Query."""
    article_id = request.args.get("id", "1")
    if not article_id.isdigit():
        return jsonify({"status": "bad_request", "message": "Invalid ID format"}), 400
    query = "SELECT id, title, author FROM articles WHERE id = %s"
    with get_db_conn() as conn, conn.cursor() as cur:
        cur.execute(query, (int(article_id),))
        row = cur.fetchone()
        return jsonify({"status": "ok", "found": bool(row)}), (200 if row else 404)

if __name__ == "__main__":
    # Chỉ lắng nghe trên loopback 127.0.0.1 để đảm bảo an toàn mạng cục bộ
    app.run(host="127.0.0.1", port=5000, debug=False)