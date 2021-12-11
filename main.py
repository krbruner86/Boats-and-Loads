from flask import Flask, request, render_template, make_response, redirect
from json2html import *
import json
import constants
import requests
import random
import datetime
import pytz
import os

from google.cloud import datastore
from google.oauth2 import id_token
from google.auth.transport import requests as google_request

app = Flask(__name__)
client = datastore.Client()
CLOUD = CLOUD_URL
CLIENT_SECRET = CLIENT_SUPER_SECRET
CLIENT_ID = CLIENT_SUPER_ID
HTTP_VERSION = "https://"
tz = pytz.timezone('US/Eastern')


def verify_jwt(token):
    try:
        # Specify the CLIENT_ID of the app that accesses the backend:
        idinfo = id_token.verify_oauth2_token(token, google_request.Request(), CLIENT_ID)

        # ID token is valid. Get the user's Google Account ID from the decoded token.
        # userid = idinfo['sub']
    except ValueError as e:
        # Invalid token
        print(e)
        return json.dumps({"Error": "Invalid token"}), 401

    return idinfo


@app.route('/', methods=['GET', 'POST'])
def index():
    if request.method == 'GET':
        return render_template('index.html')
    elif request.method == 'POST':
        return request.data
    else:
        return json.dumps({"Error": "Method Not Allowed"}), 405


@app.route('/user', methods=['GET', 'POST'])
def user():
    if request.method == 'POST':

        # generate random number for state
        state = random.randrange(99999)

        # url for login redirect
        url = ('https://accounts.google.com/o/oauth2/v2/auth?'
               'response_type=code&'
               'client_id={}&'
               'scope=https://www.googleapis.com/auth/userinfo.profile&'
               'redirect_uri={}&'
               'state={}&'
               'access_type=offline&'
               'include_granted_scopes=true&'
               'prompt=consent'.format(CLIENT_ID, CLOUD, state))
        return redirect(url)
    elif request.method == 'GET':

        # get token
        code = request.args.get('code')
        res = requests.post('https://oauth2.googleapis.com/token?'
                            'code={}&'
                            'client_id={}&'
                            'client_secret={}&'
                            'redirect_uri={}&'
                            'grant_type=authorization_code'.format(code, CLIENT_ID, CLIENT_SECRET, CLOUD))

        # extract token
        res_json = json.loads(res.content)
        token = res_json['id_token']

        userid = verify_jwt(token)
        if type(userid) == tuple:
            return userid

        # search for existing user
        query = client.query(kind="users")
        query.add_filter('sub', '=', userid['sub'])
        results = list(query.fetch())

        if len(results) == 0:
            # store user in database
            new_user = datastore.entity.Entity(key=client.key('users'))
            new_user.update({"sub": userid['sub']})
            client.put(new_user)

        # return valid token result
        return render_template('user.html', jwt=res_json['id_token'], id=userid['sub'])
    else:
        return json.dumps({"Error": "Method Not Allowed"}), 405


@app.route('/users', methods=['GET'])
def users_get():
    if request.method == 'GET':
        query = client.query(kind="users")
        results = list(query.fetch())
        return render_template('users.html', users=results)
    else:
        return json.dumps({"Error": "Method Not Allowed"}), 405


@app.route('/boats', methods=['POST', 'GET'])
def boats_get_post():
    if request.method == 'POST':

        token = request.headers.get('Authorization')
        # if token is not present
        if token is None:
            res = make_response(json.dumps({"Error": "token not provided"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res

        user_info = verify_jwt(token[7:])
        if type(user_info) == tuple:
            res = make_response(user_info)
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res
        userid = user_info['sub']

        try:
            content = request.get_json()
        except:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        if len(content) < 3:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        try:
            new_boat = datastore.entity.Entity(key=client.key(constants.boats))
            new_boat.update({"name": content["name"],
                             "type": content["type"],
                             "length": content["length"],
                             "loads": None,
                             "owner": userid
                             })
            client.put(new_boat)
        except:
            res = make_response(json.dumps({"Error": "Invalid Key"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        # add id and self to response
        boat_key = client.key(constants.boats, int(new_boat.key.id))
        boat = client.get(key=boat_key)
        boat["id"] = int(boat.id)
        boat["self"] = HTTP_VERSION + request.host + "/boats/" + str(boat.id)

        res = make_response(boat)
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201

        return res
    elif request.method == 'GET':

        if ("*/*" != request.headers.get('Accept')) and ("application/json" != request.headers.get('Accept')):
            return json.dumps({"Error": "Not Acceptable"}), 406

        # verify token
        token = request.headers.get('Authorization')

        # return owners public boats if valid token, else return all boats
        try:
            user_info = verify_jwt(token[7:])
            query = client.query(kind=constants.boats)
            userid = user_info['sub']
            query.add_filter('owner', '=', userid)
        except:
            query = client.query(kind=constants.boats)
        # code from pagination example in notes
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        loads_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = loads_iterator.pages
        results = list(next(pages))
        if len(results) > 0:
            if loads_iterator.next_page_token:
                next_offset = q_offset + q_limit
                next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
            else:
                next_url = None

            for e in results:
                e["id"] = e.key.id
                e["self"] = HTTP_VERSION + request.host + "/boats/" + str(e.key.id)
            output = {"boats": results}
            if next_url:
                output["next"] = next_url
        else:
            output = {"boats": 'No boats have been created'}
        res = make_response(json.dumps(output))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    else:
        res = make_response(json.dumps({"Error": "Method Not Allowed"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 405
        return res


@app.route('/boats/<id>', methods=['GET', 'PATCH', 'PUT', 'DELETE'])
def boats_get_patch_delete(id):

    token = request.headers.get('Authorization')
    # if token is not present
    if token is None:
        res = make_response(json.dumps({"Error": "token not provided"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 401
        return res

    user_info = verify_jwt(token[7:])
    if type(user_info) == tuple:
        res = make_response(user_info)
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 401
        return res
    userid = user_info['sub']

    if request.method == 'GET':

        try:
            boat_key = client.key(constants.boats, int(id))
            boat = client.get(key=boat_key)
            if boat['owner'] != userid:
                res = make_response(json.dumps({"Error": "boat not owned by this owner"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 401
                return res
            boat["id"] = boat.key.id
            boat["self"] = HTTP_VERSION + request.host + "/boats/" + str(boat.id)
        except:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res

        res = make_response(boat)
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'PATCH':

        try:
            content = request.get_json()
        except:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
        if boat['owner'] != userid:
            res = make_response(json.dumps({"Error": "boat not owned by this owner"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res

        # make sure all fields are present
        if len(content) == 0:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        # update boat
        for key in content:
            if key == 'id' or key == 'owner':
                res = make_response(json.dumps({"Error": "Cannot update 'id' or 'owner' fields"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 403
                return res
            elif key not in ['name', 'type', 'length']:
                res = make_response(json.dumps({"Error": "Cannot add new fields"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 400
                return res
            boat.update({key: content[key]})

        client.put(boat)

        boat["id"] = boat.key.id
        boat["self"] = HTTP_VERSION + request.host + "/boats/" + str(boat.id)
        res = make_response(json.dumps(boat))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    elif request.method == 'PUT':

        try:
            content = request.get_json()
        except:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if boat is None:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
        if boat['owner'] != userid:
            res = make_response(json.dumps({"Error": "boat not owned by this owner"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res

        # make sure all fields are present
        if len(content) != 3:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        # update boat
        for key in content:
            if key == 'id':
                res = make_response(json.dumps({"Error": 'Updating ID Not Allowed'}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 403
                return res
            elif key not in ['name', 'type', 'length']:
                res = make_response(json.dumps({"Error": "Invalid Key"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 400
                return res
            boat.update({key: content[key]})

        client.put(boat)

        boat["id"] = boat.key.id
        boat["self"] = HTTP_VERSION + request.host + "/boats/" + str(boat.id)
        res = make_response({"url": boat["self"]})
        res.headers.set('Content-Type', 'application/json')
        res.headers.set('LOCATION', boat["self"])
        res.status_code = 303
        return res
    elif request.method == 'DELETE':

        boat_key = client.key(constants.boats, int(id))
        boat = client.get(key=boat_key)
        if not boat:
            res = make_response(json.dumps({"Error": "No boat with this boat_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
        if boat['owner'] != userid:
            res = make_response(json.dumps({"Error": "boat not owned by this owner"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 401
            return res

        # remove loads if necessary
        if boat["loads"] is not None:
            load_list = list(boat["loads"])
            for load_loc in load_list:
                load_id = load_list[0]["id"]
                load_key = client.key(constants.loads, int(load_id))
                load = client.get(key=load_key)

                # disassociate load from boat
                load.update({"carrier": None})
                client.put(load)

        client.delete(boat)
        return '', 204
    else:
        res = make_response(json.dumps({"Error": "Method Not Allowed"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 405
        return res


@app.route('/loads', methods=['POST', 'GET'])
def loads_get_post():
    if request.method == 'POST':
        content = request.get_json()

        if len(content) == 0:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        for key in content:
            if content[key] is None or "volume" not in content or "content" not in content:
                res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                         "attributes"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 400
                return res

        current_date = datetime.datetime.now(tz)

        new_load = datastore.entity.Entity(key=client.key(constants.loads))
        new_load.update({"volume": content["volume"], "content": content["content"], "carrier": None,
                         "creation_date": current_date.strftime("%m/%d/%Y")})
        client.put(new_load)

        # add id and self to response
        load_key = client.key(constants.loads, int(new_load.key.id))
        load = client.get(key=load_key)
        load_dict = dict(load)
        load_dict["id"] = int(load.id)
        load_dict["self"] = HTTP_VERSION + request.host + "/loads/" + str(load.id)
        res = make_response(json.dumps(load_dict))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 201
        return res
    elif request.method == 'GET':
        # code from pagination example in notes
        query = client.query(kind=constants.loads)
        q_limit = int(request.args.get('limit', '5'))
        q_offset = int(request.args.get('offset', '0'))
        loads_iterator = query.fetch(limit=q_limit, offset=q_offset)
        pages = loads_iterator.pages
        results = list(next(pages))
        if loads_iterator.next_page_token:
            next_offset = q_offset + q_limit
            next_url = request.base_url + "?limit=" + str(q_limit) + "&offset=" + str(next_offset)
        else:
            next_url = None

        for e in results:
            e["id"] = e.key.id
            e["self"] = HTTP_VERSION + request.host + "/loads/" + str(e.key.id)
        output = {"loads": results}
        if next_url:
            output["next"] = next_url
        res = make_response(json.dumps(output))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    else:
        res = make_response(json.dumps({"Error": "Method Not Allowed"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 405
        return res


@app.route('/loads/<id>', methods=['GET', 'PATCH', 'DELETE'])
def loads_get_delete(id):
    if request.method == 'GET':
        try:
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)
            load["id"] = load.key.id
            load["self"] = HTTP_VERSION + request.host + "/loads/" + str(load.id)
            res = make_response(json.dumps(load))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 200
            return res
        except:
            res = make_response(json.dumps({"Error": "No load with this load_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
    elif request.method == 'DELETE':
        try:
            load_key = client.key(constants.loads, int(id))
            load = client.get(key=load_key)

            # remove load from boat if necessary
            if load["carrier"] is not None:
                boat_key = client.key(constants.boats, int(load["carrier"]["id"]))
                boat = client.get(key=boat_key)

                load_list = list(boat["loads"])
                for load_loc in load_list:
                    if int(id) == int(load_list[0]["id"]):
                        load_list.remove(load_loc)

                        # remove load from boat
                        boat.update({"loads": load_list})
                        client.put(boat)
            client.delete(load)
            return '', 204
        except:
            res = make_response(json.dumps({"Error": "No load with this load_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
    elif request.method == 'PATCH':

        try:
            content = request.get_json()
        except:
            res = make_response(json.dumps(
                {"Error": "The request object is missing at least one of the required attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400
            return res

        load_key = client.key(constants.loads, int(id))
        load = client.get(key=load_key)
        if load is None:
            res = make_response(json.dumps({"Error": "No load with this load_id exists"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res

        # make sure all fields are present
        if len(content) == 0:
            res = make_response(json.dumps({"Error": "The request object is missing at least one of the required "
                                                     "attributes"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 400

        # update boat
        for key in content:
            if key == 'id' or key == 'carrier':
                res = make_response(json.dumps({"Error": "Cannot update 'id' or 'carrier' fields"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 403
                return res
            elif key not in ['volume', 'content']:
                res = make_response(json.dumps({"Error": "Cannot add new fields"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 400
                return res
            load.update({key: content[key]})

        client.put(load)

        load["id"] = load.key.id
        load["self"] = HTTP_VERSION + request.host + "/loads/" + str(load.id)
        res = make_response(json.dumps(load))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 200
        return res
    else:
        res = make_response(json.dumps({"Error": "Method Not Allowed"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 405
        return res


@app.route('/boats/<boat_id>/loads/<load_id>', methods=['PUT', 'DELETE'])
def boats_loads_put_delete(boat_id, load_id):
    if request.method == "PUT":
        try:
            load_key = client.key(constants.loads, int(load_id))
            load = client.get(key=load_key)

            load_dict = {
                "id": int(load.key.id),
                "self": HTTP_VERSION + request.host + "/loads/" + str(load.id)
            }

            boat_key = client.key(constants.boats, int(boat_id))
            boat = client.get(key=boat_key)

            if boat is None:
                res = make_response(json.dumps({"Error": "Invalid boat_id or load_id"}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 404
                return res

            # add boat to load
            if load["carrier"] is not None:
                res = make_response(json.dumps({"Error": "Load already assigned to a boat."}))
                res.headers.set('Content-Type', 'application/json')
                res.status_code = 403
                return res
            else:
                update_load_boat_dict = {"id": int(boat.id), "name": boat["name"],
                                         "self": HTTP_VERSION + request.host + "/boats/" + str(boat.id)}

                load.update({"carrier": update_load_boat_dict})
                client.put(load)

            load_list = boat["loads"]

            # add load to boat
            if load_list is None:
                load_list = [load_dict]
            else:
                load_list.append(load_dict)

            boat.update({"loads": load_list})
            client.put(boat)

            return '', 200
        except:
            res = make_response(json.dumps({"Error": "Invalid boat_id or load_id"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res
    elif request.method == "DELETE":
        load_key = client.key(constants.loads, int(load_id))
        load = client.get(key=load_key)

        if load is None:
            res = make_response(json.dumps({"Error": "Invalid load_id"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res

        boat_key = client.key(constants.boats, int(boat_id))
        boat = client.get(key=boat_key)

        if boat is None:
            res = make_response(json.dumps({"Error": "Invalid boat_id"}))
            res.headers.set('Content-Type', 'application/json')
            res.status_code = 404
            return res

        load_list = list(boat["loads"])
        for load_loc in load_list:
            if int(load_id) == int(load_list[0]["id"]):
                load_list.remove(load_loc)

                # remove load from boat
                boat.update({"loads": load_list})
                client.put(boat)

                # disassociate load from boat
                load.update({"carrier": None})
                client.put(load)

                return '', 200
        return json.dumps({"Error": "Load not on this boat."}), 403
    else:
        res = make_response(json.dumps({"Error": "Method Not Allowed"}))
        res.headers.set('Content-Type', 'application/json')
        res.status_code = 405
        return res


if __name__ == '__main__':
    app.run(host='localhost', port=8080, debug=True)
