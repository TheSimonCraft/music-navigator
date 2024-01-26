class UnavailableResourceException(Exception):
    def __init__(self, resource_type: str, resource_id: int = None, message: str = None):
        self.resource_type = resource_type
        self.resource_id = resource_id if resource_id is not None else "Unknown"
        
        self.message = message if not message is None else f"Resource of type {self.resource_type} with ID {self.resource_id} is not available!"
        super().__init__(self.message)