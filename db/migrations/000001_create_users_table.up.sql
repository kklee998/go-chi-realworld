CREATE TABLE IF NOT EXISTS users(
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email VARCHAR(255) not null UNIQUE,
    username VARCHAR(255) not null UNIQUE,
    password text not null,
    bio text,
    image text
);