class StudentNotFoundException(Exception):
    def __init__(self, student_id: int, teacher_id: int = None, message: str = None):
        self.student_id = student_id
        self.teacher_id = teacher_id if teacher_id is not None else "Unknown"
        self.message = message if message is not None else f"Student with ID {self.student_id} was not found by the teacher with ID {self.teacher_id}!"
        
        super().__init__(message)