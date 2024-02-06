class InvalidSessionException(Exception):
    def __init__(self, token: str, message: str = None):
        self.token = token
        self.message = message if message is not None else f"Session with session token \"{self.token}\" was not found!"

        super().__init__(self.message)