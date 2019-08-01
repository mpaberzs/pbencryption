from pbencryption import Encryption
from cryptography.fernet import Fernet

mock_data = 'TESTMESSAGE'
mock_password = 'TEST'

mock_salt = b'\xb0z\x81[\xa5\x93 p\xa5o\x93\x0cO\x81\x04\x90'
mock_encrypted_cek = b'gAAAAABdFMh_NUyzUndheMkzFYGXEIgm4s3d5Kie8PPFy5aVk96Vm85yrow86lgINvMfE8PF0O_RVp-L7G27kNevBdxVbNqba_7KSRnpwcHZcAY-9qFYtdRTGpldy4QjHar07h8oJ7u9'
mock_token = b'gAAAAABdFMh_uLLLchJONbAAqPpyXoLNh1cfgwQxDj44CZQ-zmN7xfCjakpwMkfuuPhxUHAEgRes3Wi4beHQHzMTYCweD-YvXg=='


def test_password_bytes():
    encryption = Encryption(mock_password)

    assert type(encryption.password) == bytes


def test_salt_length():
    salt = Encryption.get_salt()

    assert len(salt) == 16


def test_salt_unique():
    salt1 = Encryption.get_salt()
    salt2 = Encryption.get_salt()

    assert salt1 != salt2


def test_kek():
    encryption = Encryption(mock_password)
    salt = Encryption.get_salt()
    key = encryption.get_kek(salt)

    assert len(key) == 44
    assert type(key) == bytes


def test_encrypt():
    encryption = Encryption(mock_password)
    encryption.encrypt(mock_data)

    assert hasattr(encryption, 'token')
    assert type(encryption.token) == bytes
    assert hasattr(encryption, 'encrypted_cek')
    assert type(encryption.encrypted_cek) == bytes
    assert hasattr(encryption, 'salt')
    assert type(encryption.salt) == bytes


def test_encrypt_cek():
    encryption = Encryption(mock_password)
    encryption.encrypt_cek(Fernet.generate_key())

    assert hasattr(encryption, 'encrypted_cek')
    assert type(encryption.encrypted_cek) == bytes
    assert hasattr(encryption, 'salt')
    assert type(encryption.salt) == bytes


def test_decrypt_cek():
    encryption = Encryption(mock_password)
    cek = encryption.decrypt_cek(mock_encrypted_cek, mock_salt)

    assert type(cek) == bytes
    assert len(cek) > 0


def test_decrypt():
    encryption = Encryption(mock_password)
    decrypted = encryption.decrypt(mock_token, mock_encrypted_cek, mock_salt)

    assert type(decrypted) == bytes
    assert decrypted == bytes(mock_data, 'UTF-8')
    assert len(decrypted) > 0
