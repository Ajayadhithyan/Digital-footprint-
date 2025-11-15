from flask import Flask, request, jsonify, send_file, send_from_directory
from flask_cors import CORS
from pymongo import MongoClient
from bson import ObjectId, Binary
from werkzeug.utils import secure_filename
from werkzeug.security import generate_password_hash, check_password_hash
import hashlib
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
import io
import PyPDF2
from docx import Document
import openpyxl
import datetime
import os
import json
import base64
import jwt
import secrets
from functools import wraps
import uuid

# Initialize Flask app
app = Flask(__name__, static_folder='frontend', static_url_path='')
CORS(app)
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', secrets.token_hex(32))
app.config['MAX_CONTENT_LENGTH'] = 100 * 1024 * 1024  # 100MB max file size

# MongoDB Configuration
MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017/')
mongodb_connected = False
db = None
files_collection = None
reports_collection = None
users_collection = None
audit_logs = None

def init_mongodb():
    global mongodb_connected, db, files_collection, reports_collection, users_collection, audit_logs
    try:
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client['forensics_toolkit']
        files_collection = db['files']
        reports_collection = db['reports']
        users_collection = db['users']
        audit_logs = db['audit_logs']
        
        # Create indexes for better query performance
        if files_collection:
            files_collection.create_index([('filename', 'text')])
            files_collection.create_index([('hashes.sha256', 1)])
            files_collection.create_index([('upload_time', -1)])
        
        mongodb_connected = True
        print("✅ Successfully connected to MongoDB")
        return True
    except Exception as e:
        print(f"❌ MongoDB Connection Error: {str(e)}")
        mongodb_connected = False
        return False

@app.route('/')
def index():
    return send_from_directory(app.static_folder, 'index.html')

if __name__ == '__main__':
    init_mongodb()
    app.run(debug=True)