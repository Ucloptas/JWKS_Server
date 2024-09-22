import unittest
from http.server import HTTPServer
from threading import Thread
from main import MyServer
#library I learned about that lets me send http requests via a program
import requests
import json


class serverTester(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Start the server and give it to another thread
        cls.server = HTTPServer(('localhost', 8080), MyServer)
        cls.thread = Thread(target=cls.server.serve_forever)
        cls.thread.start()

    #shuts down the server and reclaims the thread
    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.thread.join()

    def test_auth(self): #ensures that requests reach ok state
        response = requests.post("http://localhost:8080/auth")
        self.assertEqual(response.status_code,200)
    def test_wellKnown(self):
        response = requests.get("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 200)

    #testing things that are not allowed (patch, delete, head to auth endpoint)
    def test_patch_notAllowed(self):
        response = requests.patch("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    def test_delete_notAllowed(self):
        response = requests.delete("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    def test_head_notAllowed(self):
        response = requests.head("http://localhost:8080/auth")
        self.assertEqual(response.status_code, 405)

    #testing things that are not allowed (patch, delete, head to wellknown endpoint)
    def test_patch_notAllowed(self):
        response = requests.patch("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_delete_notAllowed(self):
        response = requests.delete("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)

    def test_head_notAllowed(self):
        response = requests.head("http://localhost:8080/.well-known/jwks.json")
        self.assertEqual(response.status_code, 405)