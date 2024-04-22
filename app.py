import traceback
from datetime import datetime, timedelta
import shortuuid
import jwt, os
import bson.json_util
from dotenv import load_dotenv
from flask import Flask, request, jsonify, render_template
from validate import validate_credentials, validate_user_details
from flask_babel import Babel, gettext as _
from cryptography.fernet import Fernet
import base64

load_dotenv()

app = Flask(__name__)
babel = Babel(app)
SECRET_KEY = os.environ.get('SECRET_KEY') or 'this is a secret'
print(SECRET_KEY)
app.config['SECRET_KEY'] = SECRET_KEY
app.config['BABEL_DEFAULT_LOCALE'] = 'en'

from models import User, Data, Verify, Shared
from auth_middleware import token_required

key = 'lDY_EEEF4z4ZhLQXIto-XRN-4YHsPq37PYHBO189ku0='
cipher_suite = Fernet(key)


def get_locale():
    # Válassza ki a kérést preferált nyelvét, vagy használja az alapértelmezett értéket
    return request.args.get('lang') or app.config['BABEL_DEFAULT_LOCALE']

babel.init_app(app, locale_selector=get_locale)

@app.route("/")
def hello():
    return "Hello World!"

@app.route("/users/register", methods=["POST"])
def add_user():
    try:
        user = request.json
        if not user:
            return {
                "message": _("Please provide user details"),
                "data": None,
                "error": _("Bad request")
            }, 400
        is_validated = validate_user_details(**user)
        if is_validated is not True:
            return {"message": is_validated, "data":None, "error":None}, 400
        if user.get('encrypt') == "1":
            # TripleDES-hez megfelelő IV/salt generálása (8 bájtos)
            user['salt'] = os.urandom(8).hex()  # TripleDES-hez
        else:
            # AES-hez vagy más alapértelmezett esethez megfelelő IV/salt generálása (16 bájtos)
            user['salt'] = os.urandom(16).hex()  # AES-hez vagy alapértelmezett
        user = User().create(**user)
        if not user:
            return {
                "message": _("User already exists"),
                "error": _("Conflict"),
                "data": None
            }, 409
        return {
            "message": _("Successfully created new user"),
            "data": user
        }, 201
    except Exception as e:
        return {
            "message": _("Something went wrong"),
            "error": str(traceback.format_exc()),
            "data": None
        }, 500

@app.route("/users/login", methods=["POST"])
def login():
    try:
        data = request.json
        if not data:
            return {
                "message": _("Please provide user details"),
                "data": None,
                "error": _("Bad request")
            }, 400
        # validate input
        is_validated = validate_credentials(data.get('email'), data.get('password'))
        if is_validated is not True:
            return dict(message=_('Invalid data'), data=None, error=is_validated), 400
        user = User().login(
            data["email"],
            data["password"]
        )
        if user:
            try:
                # token should expire after 24 hrs
                user["token"] = jwt.encode(
                    {"user_id": user["_id"]},
                    app.config["SECRET_KEY"],
                    algorithm="HS256"
                )
                return {
                    "message": _("Successfully fetched auth token"),
                    "data": user
                }
            except Exception as e:
                return {
                    "error": _("Something went wrong"),
                    "message": str(e)
                }, 500
        return {
            "message": _("Error fetching auth token!, invalid email or password"),
            "data": None,
            "error": _("Unauthorized")
        }, 404
    except Exception as e:
        return {
                "message": _("Something went wrong!"),
                "error": str(e),
                "data": None
        }, 500


@app.route("/data/", methods=["POST"])
@token_required
def add_data(current_user):
    try:
        data = request.json
        if not data:
            return {
                "message": _("Invalid data"),
                "data": None,
                "error": _("Bad Request")
            }, 400
        # hozzáadjuk a jelenlegi dátumot és a felhasználói azonosítót
        data['last_modified'] = datetime.now().strftime("%Y-%m-%d %H:%M")
        data['user_id'] = current_user["_id"]
        #meghívjuk a data model create metódusát és létrehozzuk az adatot
        data = Data().create(**data)
        if not data:
            return {
                "message": _("failed to create a new data"),
                "data": data,
                "error": _("Conflict")
            }, 400
        return jsonify({
            "message": _("successfully created a new data"),
            "data": data
        }), 201
    except Exception as e:
        return jsonify({
            "message": _("failed to create a new data"),
            "error": str(e),
            "data": None
        }), 500

@app.route("/data/get/<data_id>", methods=["GET"])
@token_required
def get_data(current_user,data_id):
    try:
        data = Data().get_by_id(data_id)
        if not data:
            return {
                "message": _("data not found"),
                "data": None,
                "error": _("Not Found")
            }, 404
        return bson.json_util.dumps({
            "message": _("successfully retrieved a data"),
            "data": data
        })
    except Exception as e:
        return jsonify({
            "message": _("Something went wrong"),
            "error": str(e),
            "data": None
        }), 500


@app.route("/data/", methods=["GET"])
@token_required
def get_all_datas(current_user):
    try:
        print(type)
        data = Data().get_by_user_id(current_user["_id"])
        return bson.json_util.dumps({
            "data": data
        })
    except Exception as e:
        return jsonify({
            "message": _("failed to retrieve all datas"),
            "error": str(e),
            "data": None
        }), 500

@app.route("/data/<type>", methods=["GET"])
@token_required
def get_datas(current_user,type):
    try:
        print(type)
        data = Data().get_by_user_id_and_type(current_user["_id"], type)
        return jsonify({
            "message": _("successfully retrieved all data"),
            "data": data
        })
    except Exception as e:
        return jsonify({
            "message": _("failed to retrieve all data"),
            "error": str(e),
            "data": None
        }), 500

@app.route("/data/<data_id>", methods=["PUT"])
@token_required
def update_data(current_user, data_id):
    try:
        data = Data().get_by_id(data_id)
        # ellenőrizzük hogy az adat a felhasználóhoz tartozik e
        if not data or data["user_id"] != current_user["_id"]:
            return {
                "message": _("data not found for user"),
                "data": None,
                "error": _("Not found")
            }, 404
        data = request.json
        #frissítjük a legutóbb módosítva dátumot
        data['last_modified'] = datetime.now().strftime("%Y-%m-%d %H:%M")
        data = Data().update(data_id, **data)
        return jsonify({
            "message": _("successfully updated a data"),
            "data": data
        }), 201
    except Exception as e:
        return jsonify({
            "message": _("failed to update a data"),
            "error": str(e),
            "data": None
        }), 400


@app.route("/data/<data_id>", methods=["DELETE"])
@token_required
def delete_data(current_user, data_id):
    try:
        data = Data().get_by_id(data_id)
        # megnézzük hogy a felhasználóhoz tartozik e az adat mielött töröljük
        if not data or data["user_id"] != current_user["_id"]:
            return {
                "message": _("data not found for user"),
                "data": None,
                "error": _("Not found")
            }, 404
        #meghívjuk a data model delete metódusát és töröljük az adatot
        Data().delete(data_id)
        return jsonify({
            "message": _("successfully deleted a data"),
            "data": None
        }), 204
    except Exception as e:
        return jsonify({
            "message": _("failed to delete a data"),
            "error": str(e),
            "data": None
        }), 400


@app.route("/verify/", methods=["POST"])
@token_required
def add_verify(current_user):
    try:
        data = request.json
        if not data:
            return {
                "message": _("Invalid data"),
                "data": None,
                "error": "Bad Request"
            }, 400
        data['user_id'] = current_user["_id"]
        data = Verify().create(**data)
        if not data:
            return {
                "message": _("failed to create a new data"),
                "data": data,
                "error": _("Conflict")
            }, 400
        return jsonify({
            "message": _("successfully created a new data"),
            "data": data
        }), 201
    except Exception as e:
        return jsonify({
            "message": _("failed to create a new data"),
            "error": str(e),
            "data": None
        }), 500

@app.route("/verify/", methods=["GET"])
@token_required
def get_verify(current_user):
    try:
        print(type)
        data = Verify().get_by_user_id(current_user["_id"])
        return jsonify({
            "message": _("successfully retrieved a data"),
            "data": data
        })
    except Exception as e:
        return jsonify({
            "message": _("failed to retrieve a data"),
            "error": str(e),
            "data": None
        }), 500

data_store = {}



@app.route('/shared/generatelink/', methods=['POST'])
@token_required
def generate_link(current_user):
    content = request.json
    if not content or 'text' not in content:
        return jsonify({
            "message": _("The text record can't be null"),
            "data": None
        }), 400

    unique_id = shortuuid.ShortUUID().random(length=8)
    expire_at = datetime.now() + timedelta(hours=24)
    #titkosítva tároljuk az adatot amit az API tud visszafejteni
    encrypted_text = base64.b64encode(cipher_suite.encrypt(content['text'].encode('utf-8')))
    content['text'] = encrypted_text
    content['name'] = unique_id
    content["expire_at"] = expire_at
    content["email"]  = current_user["email"]
    # Adat mentése az adatbázisba
    Shared().create(**content);

    # Link generálása és visszaküldése
    link = f"192.168.0.116:5000/shared/{unique_id}"
    return jsonify({'link': link})

@app.route('/shared/<name>', methods=['GET'])
def get_shared_data(name):
    content = Shared().get_by_id(name)
    if not content:
        data = {
            'text': _("Data not found"),
            'title': _("error"),
        }
    elif datetime.now() >= content['expire_at']:
        data = {
            'text': _("Data expired"),
            'title': _("error"),
        }
    else:
        # Töröljük az adatot, mivel egyszer használatos linket generálunk
        Shared().delete(name)
        data = {
            'text': decrypt_text(content['text']),
            'title': content['email'] + _(" shared the following with you"),
        }
    # Közös adatok hozzáadása minden esethez
    data.update({
        'footer': _("Password manager share function"),
        'copi': _("copy"),
        'success': _("data copied to clipboard.")
    })

    return render_template('shared_data.html', data=data)

def decrypt_text(input):
    encrypted_text = base64.b64decode(input)
    return cipher_suite.decrypt(encrypted_text).decode('utf-8')

@app.errorhandler(403)
def forbidden(e):
    return jsonify({
        "message": _("Forbidden"),
        "error": str(e),
        "data": None
    }), 403

@app.errorhandler(404)
def forbidden(e):
    return jsonify({
        "message": _("Endpoint Not Found"),
        "error": str(e),
        "data": None
    }), 404


if __name__ == "__main__":
    app.run(debug=True, port=5000, host='0.0.0.0')
