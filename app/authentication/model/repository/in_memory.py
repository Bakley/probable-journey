class UserObj:

    def  __init__(self):
        self._store = {}

    def create(self, obj):
        item = len(self._store) + 1
        import pdb
        pdb.set_trace()
        self._store[item] = obj
        obj["id"] = item
        
        return obj
    
    @staticmethod
    def email_exists(self):
        return False
