class AuthorizationFailedException(Exception):
    def __init__(self, username: str = None, user_id: int = None, is_teacher: bool = None, requires_teacher: bool = None, message: str = None):
        self.username = username if username is not None else "Unknown"
        self.user_id = user_id if user_id is not None else "Unknown"
        self.is_teacher = is_teacher if is_teacher is not None else "Unknown"
        self.requires_teacher = requires_teacher if requires_teacher is not None else "Unknown"

        self.message = message if not message is None else f"Authentication failed for User {self.username} with id {self.user_id}!"
        super().__init__(self.message)