from __future__ import annotations

import tomllib
import unittest
from pathlib import Path
from unittest.mock import patch

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from pymysql import _auth


class MysqlAuthDependencyTests(unittest.TestCase):
    def test_project_declares_pymysql_rsa_extra(self) -> None:
        project = tomllib.loads(
            (Path(__file__).parents[1] / "pyproject.toml").read_text(encoding="utf-8")
        )

        self.assertIn("PyMySQL[rsa]>=1.1.0", project["project"]["dependencies"])

    def test_missing_crypto_fails_on_the_mysql_rsa_auth_path(self) -> None:
        with patch.object(_auth, "_have_cryptography", False):
            with self.assertRaisesRegex(
                RuntimeError,
                "'cryptography' package is required for sha256_password or"
                " caching_sha2_password auth methods",
            ):
                _auth.sha2_rsa_encrypt(b"password", b"salt", b"public-key")

    def test_installed_crypto_executes_the_mysql_rsa_auth_path(self) -> None:
        password = b"password"
        salt = b"01234567890123456789"
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

        encrypted = _auth.sha2_rsa_encrypt(password, salt, public_key)
        decrypted = private_key.decrypt(
            encrypted,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None,
            ),
        )
        salted_password = bytes(
            value ^ salt[index % len(salt)]
            for index, value in enumerate(password + b"\0")
        )

        self.assertTrue(_auth._have_cryptography)
        self.assertEqual(decrypted, salted_password)


if __name__ == "__main__":
    unittest.main()
