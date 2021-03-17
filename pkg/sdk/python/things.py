import requests
import json

import response
import errors


class Things:
    def __init__(self, url):
        self.url = url

    def create(self, thing, token):
        '''Creates thing entity in the database'''
        mf_resp = response.Response()
        http_resp = requests.post(self.url + "/things", json=thing, headers={"Authorization": token})
        if http_resp.status_code != 201:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["create"], http_resp.status_code)
        else:
            location = http_resp.headers.get("location")
            mf_resp.value = location.split('/')[2]
        return mf_resp

    def create_bulk(self, things, token):
        '''Creates multiple things in a bulk'''
        mf_resp = response.Response()
        http_resp = requests.post(self.url + "/things/bulk", json=things, headers={"Authorization": token})
        if http_resp.status_code != 201:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["create_bulk"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def get(self, thing_id, token):
        '''Gets a thing entity for a logged-in user'''
        mf_resp = response.Response()
        http_resp = requests.get(self.url + "/things/" + thing_id, headers={"Authorization": token})
        if http_resp.status_code != 200:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["get"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def construct_query(self, params):
        query = '?'
        param_types = ['offset', 'limit', 'connected']
        if params is not None:
            for pt in param_types:
                if params[pt] is not None:
                    query = query + pt + params[pt] + '&'
        return query

    def get_all(self, token, query_params=None):
        '''Gets all things from database'''
        query = self.construct_query(query_params)
        url = self.url + '/things' + query
        mf_resp = response.Response()
        http_resp = requests.get(url, headers={"Authorization": token})
        if http_resp.status_code != 200:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["get_all"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def get_by_channel(self, chanID, params, token):
        '''Gets all things to which a specific thing is connected to'''
        query = self.construct_query(params)
        url = self.url + "/channels/" + chanID + '/things' + query
        mf_resp = response.Response()
        http_resp = requests.post(url, headers={"Authorization": token})
        if http_resp.status_code != 201:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["get_by_channel"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def update(self, thing_id, token, thing):
        '''Updates thing entity'''
        http_resp = requests.put(self.url + "/things/" + thing_id, json=thing, headers={"Authorization": token})
        mf_resp = response.Response()
        if http_resp.status_code != 200:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["update"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def delete(self, thing_id, token):
        '''Deletes a thing entity from database'''
        http_resp = requests.delete(self.url + "/things/" + thing_id, headers={"Authorization": token})
        mf_resp = response.Response()
        if http_resp.status_code != 204:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["delete"], http_resp.status_code)
        return mf_resp

    def connect(self, channel_ids, thing_ids, token):
        '''Connects thing and channel'''
        payload = {
          "channel_ids": [channel_ids],
          "thing_ids": [thing_ids]
        }
        http_resp = requests.post(self.url + "/connect", headers={"Authorization": token}, json=payload)
        mf_resp = response.Response()
        if http_resp.status_code != 201:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["connect"], http_resp.status_code)
        else:
            mf_resp.value = http_resp.json()
        return mf_resp

    def disconnect(self, channel_ids, thing_ids, token):
        '''Disconnect thing and channel'''
        http_resp = requests.delete(self.url + "/channels/" + channel_ids + "/things/" + thing_ids, headers={"Authorization": token})
        mf_resp = response.Response()
        if http_resp.status_code != 204:
            mf_resp.error.status = 1
            mf_resp.error.message = errors.handle_error(errors.users["disconnect"], http_resp.status_code)
        return mf_resp
