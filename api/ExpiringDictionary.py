import time


class ExpiringDictionary(dict):
    def __init__(self, *args):
        self.__tick()
        dict.__init__(self, args)

    def get(self, __key):
        self.__tick()
        return self.get(__key)[0]

    def __getitem__(self, item):
        self.__tick()
        return self.__getitem__(item)[0]

    def __setitem__(self, key, value):
        self.__tick()
        self.__setitem__(key, (value, time.time() + 60))

    def add_item(self, key, value, seconds: int = 60):
        self.__tick()
        self.setdefault(key, (value, time.time() + seconds))

    def __tick(self):
        for key, value in self:
            if value[1] < time.time(): self.__delitem__(key)
