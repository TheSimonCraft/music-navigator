import os
import psycopg2
from dotenv import load_dotenv
import bcrypt
import secrets
import base64

from .Exceptions.Database import *


class DatabaseConnection:

    def __init__(self):
        load_dotenv()

        self.connection = psycopg2.connect(
            host=os.environ.get('PG_HOST'),
            port=os.environ.get('PG_PORT'),
            user=os.environ.get('PG_USER'),
            password=os.environ.get('PG_PASSWORD'),
            database=os.environ.get('PG_DATABASE'),
            sslmode='prefer'
        )
        self.connection.autocommit = False
        self.cursor = self.connection.cursor()

    def setup(self):
        self.cursor.execute(open("../Database/music_navigator_db_setup.sql", 'r').read())
        self.connection.commit()

    def __fetch_many(self, table: str, count: int = 10, failed_exception: Exception = None, *fetch,
                     **selection) -> list:
        """
        A basic function to fetch multiple sets of values from a database
        :param table: The table to fetch from
        :param count: The number of results that should be returned, 0 for all
        :param failed_exception: The exception to be thrown if the statement returns nothing
        :param fetch: The names of the values to be fetched
        :param selection: Name and value of the filter keys
        :return: A list containing all results
        """
        statement = f"SELECT {','.join(fetch)} FROM {table}"
        if len(selection) >= 1:
            args = [f"{list(selection.keys())[i]}=%s" for i in range(len(selection.keys()))]
            statement += f" WHERE {' AND '.join(args)}"
        self.cursor.execute(statement, tuple(selection.values()))
        if self.cursor.rowcount == 0:
            if failed_exception is not None:
                self.connection.commit()
                raise failed_exception
            else:
                self.connection.commit()
                return []
        self.connection.commit()
        return self.cursor.fetchmany(count) if count > 0 else self.cursor.fetchall()

    def __fetch(self, table: str, failed_exception: Exception = None, *fetch, **selection) -> tuple:
        """
        A basic function to fetch one set of values from a database
        :param table: The table to fetch from
        :param failed_exception: The exception to be thrown if the statement returns nothing
        :param fetch: The names of the values to be fetched
        :param selection: Name and value of the filter keys
        :return: A tuple containing the result
        """
        result = self.__fetch_many(table, 1, failed_exception, *fetch, **selection)
        self.connection.commit()
        return result[0] if result is not None else None

    # ----- SESSIONS -----

    def create_session(self, username: str, password: str) -> str:
        """
        Basic function used to authenticate a user and create a session
        :param username: The users username
        :param password: The users password as plain text
        :return: Session token that should be used when making further requests
        """

        if self.authenticate(username, password):
            token = secrets.token_urlsafe(64)
            self.cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
            while self.cursor.rowcount != 0:
                token = secrets.token_urlsafe(64)
                self.cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
            userId, = self.__fetch("users", UnknownUserException(username), "user_id", username=username)
            self.cursor.execute("INSERT INTO sessions VALUES (%s, %s)", (token, userId))
            self.connection.commit()
            return token
        else:
            self.connection.commit()
            raise AuthenticationFailedException(username, password)

    def delete_session(self, token: str):
        self.cursor.execute("DELETE * FROM sessions WHERE token = %s", (token,))
        if self.cursor.rowcount == 0: raise InvalidSessionException(token)
        self.cursor.commit()

    def authorize(self, username: str, token: str, requires_teacher: bool) -> bool:
        """
        A basic function to authorize user actions
        :param username: The users username
        :param token: The users session token
        :param requires_teacher: Whether the action requires the user to be a teacher
        :return: Whether the user is permitted to do that action
        """
        user_id, is_teacher = self.__fetch("users", UnknownUserException(username), "user_id", "is_teacher",
                                           username=username)
        session_user_id, = self.__fetch("sessions", InvalidSessionException(token), "user_id", token=token)
        self.connection.commit()
        if user_id == session_user_id and (not requires_teacher or is_teacher):
            return True
        else:
            return False

    def authenticate(self, username, password) -> bool:
        """
        A basic function to authenticate a user
        :param username: The users username
        :param password: The users password
        :return: A boolean whether the user is authenticated or not
        """

        self.cursor.execute("SELECT password, salt FROM users WHERE username=%s", (username,))
        t = self.__fetch("users", None, "password", "salt", username=username)
        if t is None:
            return False
        else:
            db_pwhash, salt = t
        pwhash = bcrypt.hashpw(password.encode('ascii'), salt.encode('ascii'))
        if pwhash.decode("ascii") != db_pwhash: return False
        self.connection.commit()
        return True

    def check_token(self, token: str) -> bool:
        """
        Check whether the token is valid or not
        :param token: The session token to be validated
        :return: Whether the token is valid or not
        """
        result = self.__fetch("sessions", None, "*", token=token) is not None
        self.connection.commit()
        return result

    # ----- USERS -----

    def create_user(self, username: str, password: str, is_teacher: bool) -> str:
        """
        A basic function to register and login a new user in the database
        :param username: The users username, must be globally unique
        :param password: The users password, used to authenticate later on
        :param is_teacher: Whether the user registers as a teacher or not
        :return: Session token that should be used when making further requests
        """

        salt = bcrypt.gensalt()
        password_bytes = password.encode('ascii')
        pwhash = bcrypt.hashpw(password=password_bytes, salt=salt).decode('ascii')
        try:
            salt = salt.decode('ascii')
            self.cursor.execute("INSERT INTO users(username, password, salt, is_teacher) VALUES (%s, %s, %s, %s)",
                                (username, pwhash, salt, is_teacher))
        except psycopg2.errors.UniqueViolation:
            self.connection.commit()
            raise UnavailableUsernameException(username)
        finally:
            self.connection.commit()
            return self.create_session(username, password)

    def delete_user(self, username: str, password: str, token: str):
        """
        A basic function to delete a user after authorization
        :param username: The users username
        :param password: The users password
        :param token: The users session token
        :return: None
        """
        user_id, = self.__fetch("sessions", InvalidSessionException(token=token), "user_id", token=token)

        db_username, db_pwhash, salt = self.__fetch("users", UnknownUserException(user_id=user_id), "username",
                                                    "password", "salt", user_id=user_id)

        pwhash = bcrypt.hashpw(password.encode('ascii'), salt.encode('ascii')).decode('ascii')
        if pwhash != db_pwhash or username != db_username:
            self.connection.commit()
            raise AuthenticationFailedException(username=username, password=password)
        self.connection.commit()
        self.delete_all_songs(token)
        self.cursor.execute("DELETE FROM teacher_student_rels WHERE teacher_id = %s OR student_id = %s",
                            (user_id, user_id))
        self.cursor.execute("DELETE FROM sessions WHERE user_id = %s", (user_id,))
        self.cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))
        self.connection.commit()

    def get_session_username(self, token: str) -> str:
        """
        A basic function to retrieve a users username by a session token
        :param token: The users session token
        :return: The users username
        """
        user_id, = self.__fetch("sessions", InvalidSessionException(token=token), "user_id", token=token)
        username, = self.__fetch("users", UnknownUserException(user_id=user_id), "username", user_id=user_id)
        self.connection.commit()
        return username

    def get_user_id(self, username: str) -> int:
        """
        A basic function to retrieve a users ID by his username
        :param username: The users username
        :return: The users ID
        """
        result = self.__fetch("users", UnknownUserException(username=username), "user_id", username=username)[0]
        self.connection.commit()
        return result

    def change_username(self, password: str, new_username: str, token: str):
        """
        A basic function to change a users username
        :param password: The users password
        :param new_username: The users new username
        :param token: The users session token
        :return: None
        """
        username = self.get_session_username(token)
        if not self.authenticate(username, password):
            self.connection.commit()
            raise AuthenticationFailedException(username, password)
        self.__fetch("users", UnavailableUsernameException(new_username), "*", username=new_username)
        user_id = self.get_user_id(username)
        self.cursor.execute("UPDATE users SET username = %s WHERE user_id = %s", (new_username, user_id))
        self.connection.commit()

    def change_password(self, old_password: str, new_password: str, token: str):
        """
        A basic function to change a users password
        :param old_password: The users current password
        :param new_password: The users new password
        :param token: The users session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authenticate(username, old_password):
            self.connection.commit()
            raise AuthenticationFailedException(username, old_password)
        salt = bcrypt.gensalt()
        new_pw_hash = bcrypt.hashpw(new_password.encode('ascii'), salt)
        self.cursor.execute("UPDATE users SET password=%s, salt=%s WHERE user_id = %s",
                            (new_pw_hash.decode('ascii'), salt.decode('ascii'), user_id))
        self.connection.commit()

    def is_teacher(self, token: str) -> bool:
        """
        A basic function to check whether a user is a teacher
        :param token: The users session token
        :return: Whether the student is a teacher
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, False):
            self.connection.commit()
            raise AuthenticationFailedException(username)
        return self.authorize(username, token, True)

    # ----- SONGS -----

    def is_owner(self, song_id: int, user_id: int) -> bool:
        """
        A basic function to check whether a user is owner of a song
        :param song_id: The ID of the song to be checked
        :param user_id: The ID of the user to be checked
        :return: Whether the user is owner of the song
        """
        result = self.__fetch("songs", None, "*", song_id=song_id, teacher_id=user_id) is not None
        self.connection.commit()
        return result

    def has_access(self, song_id: int, user_id: int) -> bool:
        result = self.__fetch("student_song_rels", None, "*", song_id=song_id,
                              student_id=user_id) is not None or self.is_owner(song_id, user_id)
        self.connection.commit()
        return result

    def create_song(self, song_name: str, song_base64: str, token: str):
        """
        A basic function used to store a new song by name and id
        :param song_name: The display name of the song to be stored
        :param song_base64: The song itself, a musicxml file encoded with base64
        :param token: The users session token
        :return: None
        """

        username = self.get_session_username(token)
        if not self.authorize(username, token, False):
            self.connection.commit()
            raise AuthorizationFailedException(username)
        user_id, = self.get_user_id(username)

        song_bytes = base64.b64decode(song_base64.encode('ascii'))
        song = song_bytes.decode('ascii')

        self.cursor.execute("INSERT INTO songs(song_name, teacher_id) VALUES (%s, %s) RETURNING song_id",
                            (song_name, user_id))
        song_id, = self.cursor.fetchone()
        with open(f'./songs/{song_id}.xml', 'w') as f:
            f.write(song)
            f.flush()
            f.close()
        self.connection.commit()

    def update_song(self, song_id: int, new_title: str, token: str):
        """
        A basic function to update a songs title
        :param song_id: The songs ID
        :param new_title: The title the song is supposed to have
        :param token: The users session token
        :return: None
        """
        username = self.get_session_username(token)
        if not self.authorize(username, token, False):
            self.connection.commit()
            raise AuthorizationFailedException(username)
        user_id, = self.get_user_id(username)
        if not self.is_owner(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id)

        self.cursor.execute("UPDATE songs SET song_name = %s WHERE song_id = %s", (new_title, song_id))
        self.connection.commit()

    def delete_song(self, song_id: int, token: str):
        """
        A basic function to delete a single song
        :param song_id: The songs ID
        :param token: The users session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.is_owner(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id)
        self.cursor.execute("DELETE FROM student_song_rels WHERE song_id = %s", (song_id,))
        self.cursor.execute("DELETE FROM songs WHERE song_id = %s AND teacher_id = %s", (song_id, user_id))
        self.connection.commit()

    def delete_all_songs(self, token: str):
        """
        A basic function to delete all songs of a specified user
        :param token: The users session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        song_ids = self.__fetch_many("songs", 0, None, "song_id", teacher_id=user_id)
        for song_id in song_ids:
            os.remove(f"./songs/{song_id}.xml")
            self.cursor.execute("DELETE FROM student_song_rels WHERE song_id = %s OR student_id = %s",
                                (song_id, user_id))
        self.cursor.execute("DELETE FROM songs WHERE teacher_id = %s", (user_id,))
        self.connection.commit()

    def fetch_song(self, song_id: int, token: str) -> str:
        """
        A basic function to retrieve a Base64 Encoded MusicXML-File
        :param song_id: The songs ID
        :param token: The users session token
        :return:
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        self.__fetch("songs", UnavailableResourceException("Song", song_id), "*", song_id=song_id)
        if not self.has_access(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id)

        path = f"./songs/{song_id}.xml"
        if not os.path.isfile(path):
            self.connection.commit()
            raise UnavailableResourceException("Song", song_id)
        with open(path, 'r') as f:
            result = base64.b64encode(f.read().encode('ascii'))
        self.connection.commit()
        return result.decode('ascii')

    def fetch_song_name(self, song_id: int, token: str) -> str:
        """
        A basic function to retrieve a songs title
        :param song_id: The songs ID
        :param token: The users session token
        :return: The songs name as a string
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        name, = self.__fetch("songs", UnavailableResourceException("Song", song_id), "song_name", song_id=song_id)
        if not self.has_access(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id)
        else:
            self.connection.commit()
            return name

    def fetch_owned_songs(self, token: str) -> dict:
        """
        A basic function to retrieve all songs a user owns
        :param token: The users session token
        :return: A dict (ID, name) of all owned songs
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        result = self.__fetch_many("songs", 0, UnavailableResourceException("Song"), "song_id", "song_name",
                                   teacher_id=user_id)
        songs = {}
        for key, value in result: songs[key] = value
        self.connection.commit()
        return songs

    # TODO: Check again, especially if the list of tuples was unpacked correctly
    def fetch_available_songs(self, token: str) -> dict:
        """
        A basic functions to retrieve all songs available to a user
        :param token: The users session token
        :return: A dictionary (ID, name) of all available song
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        song_ids = self.__fetch_many("songs", 0, None, "song_id", teacher_id=user_id)
        song_ids.append(self.__fetch_many("student_song_rels", 0, None, "song_id", student_id=user_id))
        result = {}
        for song_id in song_ids:
            result[song_id] = self.__fetch("songs", UnavailableResourceException("Song", song_id), "song_name",
                                           song_id=song_id)
        self.connection.commit()
        return result

    # ----- Students -----
    def is_student(self, student_id: int, teacher_id: int) -> bool:
        """
        A basic function to check whether a user is a teachers student
        :param student_id: The ID of the student to check
        :param teacher_id: The ID of the teacher
        :return: Whether the student is the teachers student
        """
        self.__fetch("teacher_student_rels", None, "*", teacher_id=teacher_id, student_id=student_id)
        result = True if self.cursor.rowcount > 0 else False
        self.connection.commit()
        return result

    def join_teacher(self, teacher_id: int, token: str):
        """
        A basic function to create a teacher student relation
        :param teacher_id: The teachers user_id
        :param token: The students session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, False):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, False)
        self.cursor.execute("DELETE FROM teacher_student_rels WHERE student_id = %s", (user_id,))
        self.cursor.execute("INSERT INTO teacher_student_rels (teacher_id, student_id) VALUES %s, %s",
                            (teacher_id, user_id))
        self.connection.commit()

    def leave_teacher(self, token: str):
        """
        A basic function to end a teacher student relation
        :param token: The students session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, False):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, False)
        self.cursor.execute("DELETE FROM teacher_student_rels WHERE student_id = %s", (user_id,))
        self.connection.commit()

    def remove_student(self, student_id: int, token: str):
        """
        A basic function to remove a student relationship
        :param student_id: The ID of the student to be removed from the class
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        self.revoke_by_student(student_id, token)
        self.cursor.execute("DELETE FROM teacher_student_rels WHERE teacher_id = %s AND student_id = %s",
                            (user_id, student_id,))
        self.connection.commit()

    def remove_all_students(self, token: str):
        """
        A basic function to remove all students from a teachers class
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        for student_id in self.fetch_all_students(token):
            self.remove_student(student_id, token)
        self.connection.commit()

    def fetch_student_name(self, student_id: int, token: str) -> str:
        """
        A basic function to fetch a students name
        :param student_id: The ID of the student to fetch the name from
        :param token: The teachers session token
        :return: The students name
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_student(student_id, user_id):
            self.connection.commit()
            raise StudentNotFoundException(student_id, user_id)
        result, = self.__fetch("users", StudentNotFoundException(student_id, user_id), "username", user_id=student_id)
        self.connection.commit()
        return result

    def fetch_all_students(self, token: str) -> dict:
        """
        A basic function to fetch all students of a teacher
        :param token: The teachers session token
        :return: A dict (ID, name) of all students of the teacher
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        student_ids = self.__fetch_many("teacher_student_rels", 0, None, "student_id", teacher_id=user_id)
        result = {student_id: self.fetch_student_name(student_id, token) for student_id in student_ids}
        self.connection.commit()
        return result

    # ----- Shares -----

    def check_share_permission(self, teacher_id: int, student_id: int, song_id: int) -> bool:
        """
        A basic function to check whether the teacher is permitted to share a song with a student
        :param teacher_id: The teachers user ID
        :param student_id: The students user ID
        :param song_id: The songs ID
        :return: Whether the teacher is permitted to share the song, throws exception if user is not his student
        """
        if not self.is_owner(song_id, teacher_id):
            self.connection.commit()
            return False
        if not self.is_student(student_id, teacher_id):
            self.connection.commit()
            raise StudentNotFoundException(student_id, teacher_id)
        return True

    def add_share(self, student_id: int, song_id: int, token: str):
        """
        A basic function to share  a song with a student
        :param student_id: The students user ID
        :param song_id: The songs ID
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.check_share_permission(user_id, student_id, song_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id)
        self.cursor.execute("INSERT INTO student_song_rels(student_id, song_id) VALUES %s, %s", (student_id, song_id))
        self.connection.commit()

    def revoke_share(self, student_id: int, song_id: int, token: str):
        """
        A basic function to revoke a song share
        :param student_id: The students user ID
        :param song_id: The songs ID
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_owner(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id, True)
        if not self.is_student(student_id, user_id):
            self.connection.commit()
            raise StudentNotFoundException(student_id, user_id)
        self.cursor.execute("DELETE FROM student_song_rels WHERE student_id = %s AND song_id = %s",
                            (student_id, song_id))
        self.connection.commit()

    def revoke_by_student(self, student_id: int, token: str):
        """
        A basic function to revoke all song shares with a student
        :param student_id: The students user ID
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_student(student_id, user_id):
            self.connection.commit()
            raise StudentNotFoundException(student_id, user_id)
        self.cursor.execute("DELETE FROM student_song_rels WHERE student_id = %s", (student_id,))
        self.connection.commit()

    def revoke_by_song(self, song_id: int, token: str):
        """
        A basic function to revoke all shares of a song
        :param song_id: The songs ID
        :param token: The teachers session token
        :return: None
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_owner(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id, True)
        self.cursor.execute("DELETE FROM student_song_rels WHERE song_id = %s", (song_id,))
        self.connection.commit()

    def fetch_shares_by_student(self, student_id: int, token: str) -> list:
        """
        A basic function to fetch all song shared with a student
        :param student_id: The students ID
        :param token: The teachers token
        :return: A list (int) of all song IDs shared with the student
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_student(student_id, user_id):
            self.connection.commit()
            raise StudentNotFoundException(student_id, user_id)
        song_ids = self.__fetch_many("student_song_rels", 0, None, "song_id", student_id=student_id)
        song_ids = filter(lambda song_id: self.is_owner(song_id, user_id), song_ids)
        self.connection.commit()
        return song_ids

    def fetch_shares_by_song(self, song_id: int, token: str) -> list:
        """
        A basic function to fetch all students a song was shared with
        :param song_id: The songs ID
        :param token: The teachers session token
        :return: A list (int) of all student IDs the song was shared with
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        if not self.is_owner(song_id, user_id):
            self.connection.commit()
            raise AccessDeniedException("Song", song_id, user_id, True)
        student_ids = self.__fetch_many("student_song_rels", 0, None, "student_id", song_id=song_id)
        student_ids = filter(lambda student_id: self.is_student(student_id, user_id), student_ids)
        self.connection.commit()
        return student_ids

    def fetch_shares(self, token: str) -> dict:
        """
        A basic function to fetch all song shares of a teacher
        :param token: The teachers session token
        :return: A dict (int, list) of all song_ids and student_ids
        """
        username = self.get_session_username(token)
        user_id = self.get_user_id(username)
        if not self.authorize(username, token, True):
            self.connection.commit()
            raise AuthorizationFailedException(username, user_id, None, True)
        songs = self.fetch_available_songs(token).keys()
        result = {}
        for song_id in songs:
            result[song_id] = self.fetch_shares_by_song(song_id, token)
        self.connection.commit()
        return result
