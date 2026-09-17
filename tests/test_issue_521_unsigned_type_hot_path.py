from unittest.mock import patch

import cgull.ast_analyzer.configuration as configuration


def test_unsigned_type_matching_preserves_supported_spellings_and_boundaries():
    custom_typedefs = {"custom_word_t", "u24_t"}

    positives = (
        "unsigned long",
        "UINT32_T",
        "const volatile uint32_t *",
        "size_t[4]",
        "char16_t",
        "CUSTOM_WORD_T",
        "const u24_t *",
    )
    negatives = (
        "signed int",
        "my_uint32_t_wrapper",
        "uint32_tx",
        "xuint32_t",
        "my_custom_word_t_wrapper",
        "custom_word_tx",
    )

    for type_name in positives:
        assert configuration.is_unsigned_type(type_name, custom_typedefs)
    for type_name in negatives:
        assert not configuration.is_unsigned_type(type_name, custom_typedefs)


def test_standard_unsigned_lookup_uses_one_regex_search_per_call():
    class CountingPattern:
        def __init__(self):
            self.search_calls = 0

        def search(self, _value):
            self.search_calls += 1
            return None

    pattern = CountingPattern()
    repetitions = 40

    with patch.object(configuration, "_STANDARD_UNSIGNED_RE", pattern):
        for _ in range(repetitions):
            assert not configuration.is_unsigned_type("const signed long *")

    assert pattern.search_calls == repetitions


def test_custom_unsigned_lookup_is_bounded_to_one_search_per_call():
    class CountingPattern:
        def __init__(self):
            self.search_calls = 0

        def search(self, _value):
            self.search_calls += 1
            return None

    standard_pattern = CountingPattern()
    custom_pattern = CountingPattern()
    custom_typedefs = {"custom_word_t", "u24_t", "u48_t", "packet_count_t"}
    repetitions = 40

    with (
        patch.object(configuration, "_STANDARD_UNSIGNED_RE", standard_pattern),
        patch.object(configuration, "_custom_unsigned_re", return_value=custom_pattern),
    ):
        for _ in range(repetitions):
            assert not configuration.is_unsigned_type("const signed long *", custom_typedefs)

    assert standard_pattern.search_calls == repetitions
    assert custom_pattern.search_calls == repetitions


def test_custom_unsigned_regex_cache_reuses_normalized_typedef_set():
    configuration._custom_unsigned_re.cache_clear()
    try:
        first_typedefs = {"CUSTOM_WORD_T", "u24_t"}
        equivalent_typedefs = {"custom_word_t", "U24_T"}

        assert configuration.is_unsigned_type("volatile custom_word_t *", first_typedefs)
        first = configuration._custom_unsigned_re.cache_info()
        assert first.misses == 1

        assert configuration.is_unsigned_type("const u24_t", equivalent_typedefs)
        second = configuration._custom_unsigned_re.cache_info()
        assert second.misses == first.misses
        assert second.hits == first.hits + 1
    finally:
        configuration._custom_unsigned_re.cache_clear()
