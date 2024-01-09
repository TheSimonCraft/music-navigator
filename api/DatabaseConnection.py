import os
import psycopg2
from dotenv import load_dotenv
import bcrypt
from uuid import uuid4
import base64

from Exceptions import *

class DatabaseConnection:



    def __init__(self):
        load_dotenv()

        self.connection = psycopg2.connect(
            host=os.environ.get('PG_HOST'),
            port=os.environ.get('PG_PORT'),
            user=os.environ.get('PG_USER'),
            password=os.environ.get('PG_PASSWORD'),
            database=os.environ.get('PG_DATABASE'),
            sslmode = 'prefer'
        )
        self.connection.autocommit = True
        self.cursor = self.connection.cursor()


    def setup(self):
        self.cursor.execute(open("../Database/music_navigator_db_setup.sql", 'r').read())
        self.connection.commit()


    # ----- SESSIONS -----

    def create_session(self, username: str, password: str) -> str:
        """
        Basic function used to authenticate a user and create a session
        :param username: The users username
        :param password: The users password as plain text
        :return: Session token that should be used when making further requests
        """

        if self.authenticate(username, password):
            token = uuid4()
            self.cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
            while self.cursor.itersize != 0:
                token = uuid4()
                self.cursor.execute("SELECT * FROM sessions WHERE token = %s", (token,))
            self.cursor.execute("SELECT user_id FROM users WHERE username = %s", (username,))
            userId = self.cursor.fetchone()
            self.cursor.execute("INSERT INTO sessions VALUES (%s, %s)", (token, userId))
            self.connection.commit()
            print(str(token))
            return str(token)
        else:
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

        self.cursor.execute("SELECT user_id, is_teacher FROM users WHERE username = %s", (username,))
        if self.cursor.itersize == 0: raise UnknownUserException(username=username)
        user_id, is_teacher = self.cursor.fetchone()
        self.cursor.execute("SELECT user_id FROM sessions WHERE token = %s", (token,))
        if self.cursor.itersize == 0: raise InvalidSessionException(token)
        session_user_id = self.cursor.fetchone()
        if user_id == session_user_id and (not requires_teacher or is_teacher):
            return True
        else: return False

    def authenticate(self, username, password) -> bool:
        """
        A basic function to authenticate a user
        :param username: The users username
        :param password: The users password
        :return: A boolean whether the user is authenticated or not
        """

        self.cursor.execute("SELECT password, salt FROM users WHERE username=%s", (username,))
        if self.cursor.itersize == 0: return False
        db_pwhash, salt = self.cursor.fetchone()

        pwhash = bcrypt.hashpw(password, salt)
        if pwhash != db_pwhash: return False
        return True


    # ----- USERS -----

    def create_user(self, username: str, password: str, is_teacher: bool):
        """
        A basic function to register and login a new user in the database
        :param username: The users username, must be globally unique
        :param password: The users password, used to authenticate later on
        :param is_teacher: Whether the user registers as a teacher or not
        :return: None
        """

        salt = bcrypt.gensalt()
        hash = bcrypt.hashpw(password=password, salt=salt)
        try:
            self.cursor.execute("INSERT INTO users(username, password, salt, is_teacher) VALUES (%s, %s, %s, %s)", (username, hash, salt, is_teacher))
            self.cursor.commit()
        except psycopg2.errors.UniqueViolation:
            raise UnavailableUsernameException(username)

    def delete_user(self, username: str, password: str, token: str):
        """
        A basic function to delete a user after authorization
        :param username:
        :param password:
        :param token:
        :return:
        """
        self.cursor.execute("SELECT user_id FROM sessions WHERE token = %s", (token,))
        if self.cursor.itersize == 0: raise InvalidSessionException(token=token)
        user_id = self.cursor.fetchone()

        self.cursor.execute("SELECT username, password, salt FROM users WHERE user_id = %s", (user_id))
        db_username, db_pwhash, salt = self.cursor.fetchone()

        pwhash = bcrypt.hashpw(password, salt)
        if pwhash != db_pwhash or username != db_username: raise AuthenticationFailedException(username=username, password=password)

        self.cursor.execute("DELETE FROM users WHERE user_id = %s", (user_id,))

    def check_user_is_teacher(self, token) -> bool:
        self.cursor.execute("SELECT user_id FROM sessions WHERE token = %s", (token,))
        if self.cursor.itersize == 0: raise InvalidSessionException(token)
        user_id = self.cursor.fetchone()

        self.cursor.execute("SELECT is_teacher FROM users WHERE user_id = %s", (user_id))
        return bool(self.cursor.fetchone())


    # ----- SONGS -----

    def create_song(self, song_name: str, song_base64: str, teacher_id: int):
        """
        A basic function used to store a new song by name and id
        :param song_name: The display name of the song to be stored
        :param song_base64: The song itself, a musicxml file encoded with base64
        :param teacher_id: The ID of the teacher uploading the song
        :return: None
        """

        song_bytes = base64.b64decode(song_base64)
        song = song_bytes.decode('ascii')

        self.cursor.execute("INSERT INTO songs(song_name, teacher_id) VALUES (%s, %s) RETURNING song_id", (song_name, teacher_id))
        song_id = self.cursor.fetchone()
        with open(f'./songs/{song_id}.xml', 'w') as f:
            f.write(song)
            f.flush()
            f.close()

    # def update_song