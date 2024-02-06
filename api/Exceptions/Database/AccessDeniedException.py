class AccessDeniedException(Exception):
    def __init__(self, object_type: str, object_id: int, user_id: int, user_is_teacher: bool = None, message: str = None):
        self.object_type = object_type
        self.object_id = object_id
        self.user_id = user_id
        self.user_is_teacher = user_is_teacher if not user_is_teacher is None else ("Unknown")

        self.message = message if not message is None else f"User with ID {self.user_id} does not have access to {self.object_type} with ID {self.object_id}!"
        super().__init__(self.message)