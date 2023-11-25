CREATE TABLE IF NOT EXISTS users(
    id INT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    email VARCHAR(255) not null UNIQUE,
    username VARCHAR(255) not null UNIQUE,
    bio text,
    image text
);

CREATE TABLE IF NOT EXISTS user_passwords(
    user_id INT UNIQUE,
    password VARCHAR(1024) not null,
    CONSTRAINT fk_users
      FOREIGN KEY(user_id) 
	  REFERENCES users(id)
	  ON DELETE CASCADE
);
CREATE TABLE IF NOT EXISTS user_sessions(
    user_id INT,
    session_id VARCHAR(255) not null UNIQUE,
    CONSTRAINT fk_users
      FOREIGN KEY(user_id) 
	  REFERENCES users(id)
	  ON DELETE CASCADE
);
