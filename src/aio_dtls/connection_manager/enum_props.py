import logging
from enum import Enum
from typing import List, Tuple

logger = logging.getLogger(__name__)


class Default(Enum):
    pass


class EnumProps:
    supported = []
    EnumClass = Default

    def __init__(self, wish_list=None):
        self._available: List[Tuple[str, int]] = self._init_from_list(wish_list)
        pass

    @property
    def available(self):
        return [item[1] for item in self._available]

    @property
    def default(self):
        return self.EnumClass[self.supported[0]]

    @property
    def available_values(self):
        return [hash(item[1]) for item in self._available]

    def _init_from_list(self, wish_list):
        _result = []
        if wish_list is None:
            wish_list = self.supported
        for elem in wish_list:
            try:
                prop = self.EnumClass[elem]
                _result.append((prop.name, prop.value))
            except KeyError:
                logger.warning(f'{self.__class__.__name__} not supported {elem}')
        _result = sorted(_result, key=lambda x: hash(x[1]), reverse=True)
        return _result

    def get_best(self, client_offer: list):
        _client_offer = [str(item) for item in client_offer]
        logger.debug(f'{self.__class__.__name__} selecting from {_client_offer}')
        for elem in self._available:
            if elem[0] in client_offer:
                logger.debug(f'{self.__class__.__name__} selected {elem[0]}')
                return self.EnumClass[elem[0]]
