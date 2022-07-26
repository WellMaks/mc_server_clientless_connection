import leb128
class varInt(object):
    def __init__(self, x):
        if not isinstance(x, int): raise Exception()
        self.x = leb128.u.encode(x)
    def __getitem__(self, key):
        return self.x
    def __setitem__(self, y):
        if not isinstance(y, int): raise Exception()
        self.x = leb128.u.encode(y)
    def __bytes__(self):
        return bytes(self.x)
