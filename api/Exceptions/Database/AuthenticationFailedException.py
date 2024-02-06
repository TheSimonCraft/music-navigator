class AuthenticationFailedException(Exception):
    def __init__(self, username: str, password: str, message: str = None):
        """
        Raised when the authentication process failed, for example due to wrong login credentials
        :param username: The username provided by the user
        :param password: The password as text (not as hash) provided by the user
        :param message: The error message used to describe the error, None by default
        """

        self.username = username
        self.password = password
        self.message = message if message is not None else f"Authentication for user \"{self.username}\" failed. Please check your credentials and try again!"
        super().__init__(self.message)
