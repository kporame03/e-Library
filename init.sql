CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    citizen_id VARCHAR(20) UNIQUE NOT NULL,
    firstname VARCHAR(100),
    lastname VARCHAR(100),
    email VARCHAR(100),
    mobile VARCHAR(20),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);