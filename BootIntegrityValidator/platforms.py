import six

class ProductFamily(object):
    _ISR4200 = "ISR4200"
    _ISR4300 = "ISR4300"
    _ISR4400 = "ISR4400"
    _ASR1K = "ASR1000"
    _CAT3K = "CAT3K"

    _products = {'ASR1001-HX': _ASR1K,
                 'ASR1001-X': _ASR1K,
                 'ASR1002-HX': _ASR1K,
                 'ASR1002-X': _ASR1K,
                 'ASR1013': _ASR1K,
                 'ISR4451-X/K9': _ISR4400,
                 'ISR4351/K9': _ISR4300,
                 'ISR4331/K9': _ISR4300,
                 'ISR4321/K9': _ISR4300,
                 'ISR4221/K9': _ISR4200,
                 'WS-C3650-12X48UQ': _CAT3K,
                 'WS-C3850-12XS': _CAT3K,
                 'WS-C3850-24XS': _CAT3K,
                 'WS-C3850-24XU': _CAT3K}

    @classmethod
    def find_product_by_platform(cls, platform):
        """
        Return product string based on the platform
        :param platform: str
        :return: str of product

        raise ValueError if not present
        """
        assert isinstance(platform, six.string_types), "platform should be a string type: %r" % type(platform)
        try:
            return cls._products[platform]
        except KeyError:
            raise ValueError("platform {} not found!".format(platform))