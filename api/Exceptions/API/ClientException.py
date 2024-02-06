from werkzeug.exceptions import HTTPException

class UnavailableUsernameException(HTTPException):
    code = 400
    description = "Username was already taken!"


class AuthenticationFailedException(HTTPException):
    code = 403
    description = "Authentication failed!"


class UserNotFoundException(HTTPException):
    code = 404
    description = "User not found!"


class SongNotFoundException(HTTPException):
    code = 404
    description = "Song not found!"

class InvalidSessionException(HTTPException):
    code = 400
    description = "Invalid Session"