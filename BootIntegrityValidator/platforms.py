import six


class ProductFamily(object):
    _ISR4K = "ISR4000"
    _ASR1K = "ASR1000"
    _CAT3K = "CAT3K"

    _products = {'ASR1001-HX': _ASR1K,
                 'ASR1001-X': _ASR1K,
                 'ASR1002-HX': _ASR1K,
                 'ASR1002-X': _ASR1K,
                 'ASR1006-X': _ASR1K,
                 'ASR1013': _ASR1K,
                 'ISR4451-X/K9': _ISR4K,
                 'ISR4431/K9': _ISR4K,
                 'ISR4351/K9': _ISR4K,
                 'ISR4331/K9': _ISR4K,
                 'ISR4321/K9': _ISR4K,
                 'ISR4221/K9': _ISR4K,
                 'WS-C3650-8X24PD': _CAT3K,
                 'WS-C3650-8X24UQ': _CAT3K,
                 'WS-C3650-12X48UQ': _CAT3K,
                 'WS-C3650-12X48UR': _CAT3K,
                 'WS-C3650-12X48UZ': _CAT3K,
                 'WS-C3650-24PD': _CAT3K,
                 'WS-C3650-24PDM': _CAT3K,
                 'WS-C3650-24PS': _CAT3K,
                 'WS-C3650-24TS': _CAT3K,
                 'WS-C3650-48FQM': _CAT3K,
                 'WS-C3650-48PD': _CAT3K,
                 'WS-C3650-48PQ': _CAT3K,
                 'WS-C3650-48PS': _CAT3K,
                 'WS-C3650-48TD': _CAT3K,
                 'WS-C3650-48TQ': _CAT3K,
                 'WS-C3650-48TS': _CAT3K,
                 'WS-C3850-12S': _CAT3K,
                 'WS-C3850-12X48U': _CAT3K,
                 'WS-C3850-12XS': _CAT3K,
                 'WS-C3850-24S': _CAT3K,
                 'WS-C3850-24XS': _CAT3K,
                 'WS-C3850-24XU': _CAT3K,
                 'WS-C3850-48XS': _CAT3K}

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