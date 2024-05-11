import project

def test_master_pass_key_hash():
    assert project.master_pass_key_hash("test") == "59953998e54a579be74c1b7344cd55c64981451b066a35c9d7baf5497f16d865"


def test_get_key():
    assert project.get_key() == b'NTk5NTM5OThlNTRhNTc5YmU3NGMxYjczNDRjZDU1YzY='


def test_decrypt():
    assert project.decrypt(project.encrypt("secret")) == "secret"

