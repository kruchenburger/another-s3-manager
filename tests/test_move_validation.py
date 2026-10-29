import pytest

from another_s3_manager import utils


@pytest.mark.parametrize("name", ["новая 📁", "a..b", "#+%"])
def test_new_names(name):
    assert utils.validate_new_name(name) == name


@pytest.mark.parametrize("name", ["", ".", "..", "a/b", " x", "x ", "x\n", "a" * 256])
def test_invalid_names(name):
    with pytest.raises(ValueError):
        utils.validate_new_name(name)


def test_exact_keys_and_mapping():
    assert utils.validate_source_key("a..b/é 📁 ") == "a..b/é 📁 "
    assert utils.build_destination_key("dest", "a..b/é 📁 ", "file") == "dest/é 📁 "
    assert utils.build_destination_key("", "a/b", "folder", "new") == "new/"
    assert utils.is_same_or_descendant("a/b", "a/b")
    assert utils.is_same_or_descendant("a/b/c", "a/b")
    assert not utils.is_same_or_descendant("a/bc", "a/b")


@pytest.mark.parametrize("key", ["", "/a", "a/../b", "a\x7f", "😀" * 257])
def test_invalid_keys(key):
    with pytest.raises(ValueError):
        utils.validate_source_key(key)


def test_utf8_boundary():
    assert utils.validate_source_key("😀" * 256) == "😀" * 256
    with pytest.raises(ValueError):
        utils.build_destination_key("x", "😀" * 256, "file")
