import unittest
import time
import hashlib
from fastapi.testclient import TestClient
from fastapi_imp_auth_skele import app
from fastapi_imp_auth_skele.config import config

client = TestClient(app)


def solve_challenge(challenge: str) -> str:
    return hashlib.sha256((config["AuthSecret"] + challenge).encode("utf8")).hexdigest()


class MyTestCase(unittest.TestCase):
    def test_access_denied(self):
        response = client.get("/private/resource")
        self.assertEqual(403, response.status_code)

    def test_auth(self):
        response = client.get("/public/token")
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("challenge" in data)
        challenge = data["challenge"]

        response = client.post(
            "/public/token", json={"challenge": challenge, "response": solve_challenge(challenge)}
        )
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("token" in data)
        token = data["token"]

        response = client.get("/private/resource", headers={"X-Token": token})
        self.assertEqual(200, response.status_code)
        self.assertEqual({"data": "secret-data"}, response.json())

    def test_challenge_expires(self):
        response = client.get("/public/token")
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("challenge" in data)
        challenge = data["challenge"]

        time.sleep(int(config["ChallengeTTLSeconds"]) + 1)
        response = client.post(
            "/public/token", json={"challenge": challenge, "response": solve_challenge(challenge)}
        )
        self.assertEqual(401, response.status_code)

    def test_invalid_challenge_response(self):
        response = client.get("/public/token")
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("challenge" in data)
        challenge = data["challenge"]

        response = client.post("/public/token", json={"challenge": challenge, "response": "l33t"})
        self.assertEqual(401, response.status_code)

    def test_invalid_token(self):
        response = client.get("/private/resource", headers={"X-Token": "l33t"})
        self.assertEqual(403, response.status_code)

    def test_token_expires(self):
        response = client.get("/public/token")
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("challenge" in data)
        challenge = data["challenge"]

        response = client.post(
            "/public/token", json={"challenge": challenge, "response": solve_challenge(challenge)}
        )
        self.assertEqual(200, response.status_code)
        data = response.json()
        self.assertTrue("token" in data)
        token = data["token"]

        time.sleep(int(config["TokenTTLSeconds"]) + 1)

        response = client.get("/private/resource", headers={"X-Token": token})
        self.assertEqual(403, response.status_code)


if __name__ == "__main__":
    unittest.main()
