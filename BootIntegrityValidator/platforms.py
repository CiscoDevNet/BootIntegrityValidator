__author__ = "Jay Young"
__author_email__ = "jyoungta@cisco.com"
__copyright__ = "Copyright (c) 2017 Cisco Systems, Inc."
__license__ = "MIT"


class ProductFamily(object):
    _ISR4400 = ("ISR4400", "isr4400")
    _ISR4400V2 = "isr4400v2"
    _ISR4300 = ("ISR4300", "isr4300")
    _ISR4200 = ("ISR4200", "isr4200")
    _ASR1K = ("ASR1000", "asr1000")
    _CAT3650 = ("C3650",)
    _CAT3850 = ("C3850",)
    _CAT9K = ("cat9k",)
    _CAT9KLITE = ("cat9k_lite",)
    _products = {
        "ASR1001-HX": (*_ASR1K,),
        "ASR1001-X": (*_ASR1K, "asr1001x"),
        "ASR1002-HX": (*_ASR1K, "asr1002x"),
        "ASR1002-X": (*_ASR1K,),
        "ASR1006-X": (*_ASR1K,),
        "ASR1009-X": (*_ASR1K,),
        "ASR1013": (*_ASR1K,),
        "C9200-48P": (*_CAT9K,),
        "C9200L-48P-4X": (*_CAT9KLITE,),
        "C9300-24P": (*_CAT9K,),
        "C9300-24T": (*_CAT9K,),
        "C9300-24UB": (*_CAT9K,),
        "C9300-48P": (*_CAT9K,),
        "C9300-48UXM": (*_CAT9K,),
        "C9300L-48P-4G": (*_CAT9K,),
        "C9410R": (*_CAT9K,),
        "ISR4221/K9": (*_ISR4200,),
        "ISR4321/K9": (*_ISR4300,),
        "ISR4331/K9": (*_ISR4300,),
        "ISR4351/K9": (*_ISR4300,),
        "ISR4431/K9": (*_ISR4400,),
        "ISR4451-X/K9": (*_ISR4400,),
        "ISR4461/K9": (*_ISR4400V2,),
        "WS-C3650-12X48UQ": (*_CAT3650,),
        "WS-C3650-12X48UR": (*_CAT3650,),
        "WS-C3650-12X48UZ": (*_CAT3650,),
        "WS-C3650-24PD": (*_CAT3650,),
        "WS-C3650-24PDM": (*_CAT3650,),
        "WS-C3650-24PS": (*_CAT3650,),
        "WS-C3650-24TD": (*_CAT3650,),
        "WS-C3650-24TS": (*_CAT3650,),
        "WS-C3650-48FQM": (*_CAT3650,),
        "WS-C3650-48PD": (*_CAT3650,),
        "WS-C3650-48PQ": (*_CAT3650,),
        "WS-C3650-48PS": (*_CAT3650,),
        "WS-C3650-48TD": (*_CAT3650,),
        "WS-C3650-48TQ": (*_CAT3650,),
        "WS-C3650-48TS": (*_CAT3650,),
        "WS-C3650-8X24PD": (*_CAT3650,),
        "WS-C3650-8X24UQ": (*_CAT3650,),
        "WS-C3850-12S": (*_CAT3850,),
        "WS-C3850-12X48U": (*_CAT3850,),
        "WS-C3850-12XS": (*_CAT3850,),
        "WS-C3850-24S": (*_CAT3850,),
        "WS-C3850-24XS": (*_CAT3850,),
        "WS-C3850-24XU": (*_CAT3850,),
        "WS-C3850-48XS": (*_CAT3850,),
    }

    @classmethod
    def find_product_by_platform(cls, platform):
        """
        Return product string based on the platform
        :param platform: str
        :return: str of product

        raise ValueError if not present
        """
        assert isinstance(platform, str), "platform should be a string type: %r" % type(
            platform
        )
        try:
            return cls._products[platform]
        except KeyError:
            raise ValueError("platform {} not found!".format(platform))
