class UnknownUserException(Exception):
    def __init__(self, username: str = None, user_id: int = None, message: str = None):
        self.username = username if username is not None else "Unknown"
        self.user_id = user_id if user_id is not None else "Unknown"
        self.message = message if message is not None else f"User with username \"{self.username}\" and ID \"{self.user_id}\" could not be found or doesn't exist"
        
        super().__init__(message = self.message)