class UnavailableUsernameException(Exception):
    def __init__(self, username: str, message: str = None):
        """
        Raised when the registration process fails due to an unavailable username
        :param username: The username provided by the user
        :param message: The error message used to describe the problem, None by default
        """
        self.username = username
        self.message = message if message is not None else f"Username \"{self.username}\" is not available!"
        
        super().__init__(message=self.message)