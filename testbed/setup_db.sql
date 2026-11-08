-- 1. Tạo database và user riêng cho môi trường testbed
CREATE DATABASE sqli_testbed_db;
CREATE USER testbed_user WITH ENCRYPTED PASSWORD 'local_test_pass_123';

-- Ngăn không cho user tạo bảng mới trên schema public
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO testbed_user;

\c sqli_testbed_db

-- 2. Tạo bảng dữ liệu mẫu với các kiểu dữ liệu khác nhau (INT, TEXT, NUMERIC, BOOLEAN)
CREATE TABLE products (
    id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    price NUMERIC(10, 2) NOT NULL,
    is_published BOOLEAN DEFAULT TRUE
);

CREATE TABLE articles (
    id SERIAL PRIMARY KEY,
    title VARCHAR(150) NOT NULL,
    author VARCHAR(50) NOT NULL,
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- 3. Chèn dữ liệu mẫu (Ground Truth Data)
INSERT INTO products (name, category, price, is_published) VALUES
    ('Mechanical Keyboard', 'electronics', 120.00, TRUE),
    ('USB-C Hub', 'electronics', 45.50, TRUE),
    ('Designing Data-Intensive Applications', 'books', 55.00, TRUE),
    ('Database Internals', 'books', 48.00, TRUE),
    ('Unreleased Prototype', 'electronics', 999.00, FALSE);

INSERT INTO articles (title, author, content) VALUES
    ('PostgreSQL Indexing Guide', 'alice', 'B-Tree and GIN indexes explained.'),
    ('Understanding Query Planners', 'bob', 'How EXPLAIN ANALYZE works in practice.');

-- 4. Cấp quyền tối thiểu (Least Privilege: Chỉ cho phép SELECT)
GRANT USAGE ON SCHEMA public TO testbed_user;
GRANT SELECT ON products, articles TO testbed_user;