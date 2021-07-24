import uuid
import datetime
import string
import random
from url import url_shortner
from pymongo import MongoClient
from flask import Flask, redirect
from flask_restful import reqparse
from werkzeug.security import generate_password_hash, check_password_hash


cluster = MongoClient()
db = cluster['url_shortner']
collection = db["user"]
collection_url = db["url"]


app = Flask(__name__)


@app.route('/user', methods=['POST'])
def create_user():
    # data = request.get_json()
    parser = reqparse.RequestParser()
    parser.add_argument('username')
    parser.add_argument('name')
    parser.add_argument('password')
    args = parser.parse_args()
    user = collection.find_one({"username": args['username']})
    if user:
        return {"message": "Username already exists. Try with a different username"}

    hashed_password = generate_password_hash(args['password'], method='sha256')
    # in a user collection, each document consists of name, username (unique), hashed password,
    # api_key (unique), uses_of_api_left
    collection.insert_one({"username": args["username"],
                           "password": hashed_password,
                           "name": args["name"],
                           "api_key": uuid.uuid4().hex,
                           "uses_of_apikey_left": 10})
    created_user = collection.find_one({"username": args['username']})
    return {"Message": "User created",
            "username": created_user['username'],
            "api_key": created_user["api_key"],
            "uses left of apikey": created_user["uses_of_apikey_left"]}


@app.route('/user/myapikey', methods=['POST'])
def give_api_key():
    parser = reqparse.RequestParser()
    parser.add_argument('username')
    parser.add_argument('password')
    args = parser.parse_args()
    user = collection.find_one({"username": args['username']})

    if not user or not check_password_hash(user['password'], args["password"]):
        return {"message": "username or password is incorrect"}

    return {"username": user['username'],
            "api_key": user["api_key"],
            "uses left of apikey": user["uses_of_apikey_left"]
            }


@app.route('/user/generate_apikey', methods=['POST'])
def generate_api_key():
    parser = reqparse.RequestParser()
    parser.add_argument('username')
    parser.add_argument('password')
    args = parser.parse_args()
    user = collection.find_one({"username": args['username']})

    if not user or not check_password_hash(user['password'], args["password"]):
        return {"message": "username or password is incorrect"}

    if user['uses_of_apikey_left'] > 0:
        return {"message": "previous api key is not expired. Cannot generate"}
    elif user['uses_of_apikey_left'] == 0:
        new_api_key = uuid.uuid4().hex
        collection.update_one({"username": args['username']},
                              {"$set": {"api_key": new_api_key,
                                        "uses_of_apikey_left": 10}})
        return {"new_api_key": new_api_key,
                "uses left of apikey": 10}


@app.route('/shorturl', methods=["POST"])
def create_url():
    parser = reqparse.RequestParser()
    parser.add_argument('api_key')
    parser.add_argument('original_url')
    args = parser.parse_args()

    user = collection.find_one({"api_key": args['api_key']})
    if not user:
        return {"message": "no such api key is present. Create a new user"}

    # if user is present, check if api key is exhausted, return a message
    if user['uses_of_apikey_left'] == 0:
        return {"message": "API key is expired. Create a new one"}

    tiny_url = url_shortner(args['original_url'])

    if collection_url.find_one({"ShortUrl": tiny_url}):
        if collection_url.find_one({"ShortUrl": tiny_url, "OriginalURL": args['original_url'], "username": user["username"]}):
            return {"message": "Tiny utl already exists",
                    "Tiny URL": "/".join(("http://127.0.0.1:5000", tiny_url)),
                    "Original URL": args['original_url']}
        else:
            tiny_url = url_shortner("/".join((args['original_url'], user['username'])))

            # if that also present, add random string ahead of the username till we get unique 7 digit short url
            while collection_url.find_one({"ShortUrl": tiny_url}):
                random_str = ''.join(([random.choice(string.ascii_lowercase) for i in range(4)]))
                tiny_url = url_shortner("/".join((args['original_url'], user['username'], random_str)))

    collection_url.insert_one({"ShortUrl": tiny_url,
                               "OriginalURL": args['original_url'],
                               "CreationDate": datetime.datetime.now(),
                               "ExpireTime": datetime.datetime.now()+datetime.timedelta(5),
                               "visits": 0,
                               "username": user['username']})

    # TODO - update the 'uses_of_apikey_left' in user collection
    collection.update_one({"api_key": args['api_key']},
                          {"$set": {"uses_of_apikey_left": user['uses_of_apikey_left'] - 1}})
    return {"Tiny URL": "/".join(("http://127.0.0.1:5000", tiny_url)),
            "Original URL": args['original_url'],
            "API Key uses left": user['uses_of_apikey_left'] - 1}


@app.route('/<short_url>')
def redirect_to_url(short_url):
    _url = collection_url.find_one({"ShortUrl": short_url})
    # if short url is not present in the database
    if not _url:
        return {"message": "URL does not exist"}

    # if short url present but expired
    if _url["ExpireTime"] < datetime.datetime.now():
        # delete the url
        collection.delete_one({"ShortUrl": short_url})
        return {"message": "Short URL expired. Create a new one"}

    # update the visits - increase by 1
    collection_url.update_one({"ShortUrl": short_url}, {"$set": {"visits": _url["visits"] + 1}})
    return redirect(_url['OriginalURL'])


if __name__ == '__main__':
    app.run()
