-- OBJECTS
CREATE TABLE IF NOT EXISTS users(
	user_id SERIAL PRIMARY KEY NOT NULL,
	username varchar UNIQUE NOT NULL,
	password varchar NOT NULL,
	salt char(64) UNIQUE NOT NULL,
	is_teacher bool NOT NULL
);

CREATE TABLE IF NOT EXISTS songs(
	song_id SERIAL PRIMARY KEY NOT NULL,
	song_name varchar NOT NULL,
	teacher_id int NOT NULL REFERENCES users(user_id)
);

-- RELATIONSHIPS

CREATE OR REPLACE FUNCTION fn_user_is_teacher(_user_id int)
RETURNS BOOLEAN AS
$$
	SELECT is_teacher FROM users WHERE user_id = _user_id AND is_teacher = True LIMIT 1;
$$ LANGUAGE sql;


CREATE TABLE IF NOT EXISTS teacher_student_rels (
	rel_id SERIAL PRIMARY KEY NOT NULL,
	teacher_id int REFERENCES users(user_id) CHECK(fn_user_is_teacher(teacher_id) = '1') NOT NULL,
	student_id int UNIQUE REFERENCES users(user_id) CHECK(fn_user_is_teacher(student_id) = '0') NOT NULL
);

CREATE TABLE IF NOT EXISTS student_song_rels (
	rel_id SERIAL PRIMARY KEY,
	student_id int REFERENCES users(user_id) CHECK(fn_user_is_teacher(student_id) = '0') NOT NULL,
	song_id int REFERENCES songs(song_id) NOT NULL
);

-- AUTHENTICATION

CREATE TABLE IF NOT EXISTS sessions(
	token varchar PRIMARY KEY,
	user_id int NOT NULL REFERENCES users(user_id)	
);

-- MIGRATION
CREATE TABLE IF NOT EXISTS migrations(
	migration_id SERIAL PRIMARY KEY,
	filename varchar NOT NULL
);
