
from collections.abc import MutableSequence


class TriggerList(MutableSequence):
    """This list can trigger a callback/handler function whenever its contents change"""

    def __init__(self, trigger_handler, iterable=()):
        self._list = list(iterable)
        self.trigger_handler = trigger_handler

    def __getitem__(self, key):
        return self._list.__getitem__(key)

    def __setitem__(self, key, item):
        self._list.__setitem__(key, item)
        # trigger action
        self.trigger_handler()

    def __delitem__(self, key):
        self._list.__delitem__(key)
        # trigger action
        self.trigger_handler()

    def __len__(self):
        return self._list.__len__()

    def insert(self, index, item):
        self._list.insert(index, item)
        # trigger action
        self.trigger_handler()
