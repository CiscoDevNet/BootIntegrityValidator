import six

class ProductFamily(object):
    _ISR4K = "ISR4000"
    _ASR1K = "ASR1000"
    _CAT3K = "CAT3K"

    _products = {'ISR4321/K9': _ISR4K,
                 'ISR4451/K9': _ISR4K,
                 'ISR4331/K9': _ISR4K,
                 'ISR4221/K9': _ISR4K,
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