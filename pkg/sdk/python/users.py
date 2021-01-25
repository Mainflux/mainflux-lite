import requests
import json


class Users:
    def __init__(self, url):
        self.url = url

    def create_user(self, user):
        ''' CreateUser() creates user entity in the database '''
        resp = requests.post(self.url + "/users", json=user)
        return resp.headers.get("location")

    def user(self, token):
        '''user() recieve Authorization token'''
        resp = requests.get(self.url + "/users", headers={"Authorization": token})
        return resp.content

    def create_token(self, user):
        resp = requests.post(self.url + "/tokens", json=user)
        return resp.json()["token"]

    def update_user(self, user, token):
        resp = requests.put(self.url + "/users", headers={"Authorization": token}, data=json.dumps(user))
        return resp.status_code

    def update_password(self, old_password, new_password, token):
        payload = {
          "password": old_password,
          "old_password": new_password
        }
        resp = requests.patch(self.url + "/password", headers={"Authorization": token}, data=json.dumps(payload))
        return resp
