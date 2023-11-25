CREATE TABLE users (
    id identity PRIMARY KEY,
    email text not null,
    username text not null,
    password text not null,
    bio text not null,
    image text not null
);