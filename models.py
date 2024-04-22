"""Application Models"""
import bson, os
from dotenv import load_dotenv
from pymongo import MongoClient
from werkzeug.security import generate_password_hash, check_password_hash

load_dotenv()

DATABASE_URL=os.environ.get('DATABASE_URL') or 'mongodb://localhost:27017/password_manager'
print(DATABASE_URL)
client = MongoClient(DATABASE_URL)
db = client.myDatabase

class Shared:
    def __init__(self):
        return


    def create(self, **data):
        """Create a new login"""
        new_data = db.shared.insert_one(data)
        return self.get_by_id(new_data.inserted_id)

    def delete(self, data_id):
        """Delete a book"""
        data = db.shared.delete_one({"name": data_id})
        return data

    def get_by_id(self, data_id):
        """Get a book by id"""
        new_data = db.shared.find_one({"name": data_id})
        if not new_data:
            return
        new_data["_id"] = str(new_data["_id"])
        return new_data

class Verify:
    def __init__(self):
        return

    def create(self, **data):
        """Create a new login"""
        new_data = db.verify.insert_one(data)
        return self.get_by_id(new_data.inserted_id)

    def get_by_id(self, data_id):
        """Get a book by id"""
        new_data = db.verify.find_one({"_id": bson.ObjectId(data_id)})
        if not new_data:
            return
        new_data["_id"] = str(new_data["_id"])
        return new_data

    def get_by_user_id(self, user_id):
        """Get all data by type created by a user"""
        logins = db.verify.find({"user_id": user_id})
        return [{**login, "_id": str(login["_id"])} for login in logins]


class Data:
    def __init__(self):
        return

    def create(self, **data):
        """Create a new login"""
        new_data = db.data.insert_one(data)
        return self.get_by_id(new_data.inserted_id)

    def get_by_id(self, data_id):
        """Get a book by id"""
        new_data = db.data.find_one({"_id": bson.ObjectId(data_id)})
        if not new_data:
            return
        new_data["_id"] = str(new_data["_id"])
        return new_data

    def get_by_user_id(self, user_id):
        """Get all books created by a user"""
        datas = db.data.find({"user_id": user_id}, {'user_id': 0})
        return [{**data, "_id": str(data["_id"])} for data in datas]

    def get_by_user_id_and_type(self, user_id, type):
        """Get all data by type created by a user"""
        logins = db.data.find({"user_id": user_id, "type": type}, {"name": 1,"username":1, "user_id": 1})
        return [{**login, "_id": str(login["_id"])} for login in logins]

    def delete(self, data_id):
        """Delete a book"""
        data = db.data.delete_one({"_id": bson.ObjectId(data_id)})
        return data

    def update(self, data_id, **data):
        """Update a book"""

        data = db.data.update_one(
            {"_id": bson.ObjectId(data_id)},
            {"$set": data}
        )
        data = self.get_by_id(data_id)
        return data

class User:
    """User Model"""
    def __init__(self):
        return

    def create(self, name="", email="", password="",encrypt = "", salt=""):
        """Create a new user"""
        user = self.get_by_email(email)
        if user:
            return
        new_user = db.users.insert_one(
            {
                "name": name,
                "email": email,
                "password": self.encrypt_password(password),
                "encrypt": encrypt,
                "salt": salt,
                "active": True
            }
        )
        return self.get_by_id(new_user.inserted_id)


    def get_by_id(self, user_id):
        """Get a user by id"""
        user = db.users.find_one({"_id": bson.ObjectId(user_id), "active": True})
        if not user:
            return
        user["_id"] = str(user["_id"])
        user.pop("password")
        return user

    def get_by_email(self, email):
        """Get a user by email"""
        user = db.users.find_one({"email": email, "active": True})
        if not user:
            return
        user["_id"] = str(user["_id"])
        return user


    def encrypt_password(self, password):
        """Encrypt password"""
        return generate_password_hash(password)

    def login(self, email, password):
        """Login a user"""
        user = self.get_by_email(email)
        if not user or not check_password_hash(user["password"], password):
            return
        user.pop("password")
        return user
