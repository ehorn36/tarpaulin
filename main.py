# Citation #1 for the following file:
# Date: 5/24/25
# Based on: Video demonstrations from OSU's CS 493, modules 8
# Source URL: https://canvas.oregonstate.edu/courses/1999676/pages/
#             exploration-handling-files-using-flask-2?module_item_id=25288474

# Citation #2 for the following file:
# Date: 5/24/25
# Based on: response.status_code - Python requests
# Source URL: https://www.geeksforgeeks.org/
#             response-status_code-python-requests/

# Citation #3 for the following file:
# Date: 5/24/25
# Based on: Convert Request Response to Dictionary in Python
# Source URL: https://www.geeksforgeeks.org/response-json-python-requests/

# Citation #4 for the following file:
# Date: 5/24/25
# Based on: Datastore mode client libraries
# Source URL: https://cloud.google.com/datastore/docs/reference/libraries

# Citation #5 for the following file:
# Date: 5/25/25
# Based on: How to check if file exists in Google Cloud Storage?
# Source URL: https://cloud.google.com/datastore/
#             docs/reference/libraries

# Citation #6 for the following file:
# Date: 5/25/25
# Based on: How can I determine a Python variable's type?
# Source URL: https://stackoverflow.com/questions/402504/
#             how-can-i-determine-a-python-variables-type

# Citation #7 for the following file:
# Date: 5/26/25
# Based on: create-the-jwt-validation-decorator
# Source URL: https://auth0.com/docs/quickstart/backend/python/
#             01-authorization?_ga=2.46956069.349333901.1589042886-466012638

from flask import Flask, request, jsonify, send_file
from google.cloud import datastore, storage

import requests
import json
import io
import os

from six.moves.urllib.request import urlopen
from jose import jwt
from authlib.integrations.flask_client import OAuth

app = Flask(__name__)
app.secret_key = 'SECRET_KEY'

client = datastore.Client()

# Constants
USERS = 'users'
COURSES = 'courses'
PAGE_LIMIT = 3
OFFSET = 0

# Error messages
BAD_REQUEST = {'Error': 'The request body is invalid'}          # 400
UNAUTHORIZED = {'Error': 'Unauthorized'}                        # 401
NO_PERMISSION = ({'Error': 'You don\'t have '
                  'permission on this resource'})               # 403
NOT_FOUND = {"Error": "Not found"}                              # 404
INVALID_ENROLLMENT = {"Error": "Enrollment data is invalid"}    # 409


# Assign .env variables
CLIENT_ID = os.getenv("CLIENT_ID")
CLIENT_SECRET = os.getenv("CLIENT_SECRET")
DOMAIN = os.getenv("DOMAIN")
ALGORITHMS = os.getenv("ALGORITHMS")
PHOTO_BUCKET = os.getenv("PHOTO_BUCKET")

# Update Flask config
app.config.update({
    'CLIENT_ID': CLIENT_ID,
    'CLIENT_SECRET': CLIENT_SECRET,
    'DOMAIN': DOMAIN,
    'ALGORITHMS': ALGORITHMS,
    'PHOTO_BUCKET': PHOTO_BUCKET
})

oauth = OAuth(app)
auth0 = oauth.register(
    'auth0',
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET,
    api_base_url="https://" + DOMAIN,
    access_token_url="https://" + DOMAIN + "/oauth/token",
    authorize_url="https://" + DOMAIN + "/authorize",
    client_kwargs={
        'scope': 'openid profile email',
    },
)


class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


@app.errorhandler(AuthError)
def handle_auth_error(ex):
    response = jsonify(ex.error)
    response.status_code = ex.status_code
    return response


# Verify the JWT in the request's Authorization header
def verify_jwt(request):
    if 'Authorization' in request.headers:
        auth_header = request.headers['Authorization'].split()
        token = auth_header[1]
    else:
        raise AuthError({"code": "no auth header",
                         "description":
                         "Authorization header is missing"}, 401)

    jsonurl = urlopen("https://" + DOMAIN+"/.well-known/jwks.json")
    jwks = json.loads(jsonurl.read())
    try:
        unverified_header = jwt.get_unverified_header(token)
    except jwt.JWTError:
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    if unverified_header["alg"] == "HS256":
        raise AuthError({"code": "invalid_header",
                        "description":
                            "Invalid header. "
                            "Use an RS256 signed JWT Access Token"}, 401)
    rsa_key = {}
    for key in jwks["keys"]:
        if key["kid"] == unverified_header["kid"]:
            rsa_key = {
                "kty": key["kty"],
                "kid": key["kid"],
                "use": key["use"],
                "n": key["n"],
                "e": key["e"]
            }
    if rsa_key:
        try:
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=CLIENT_ID,
                issuer="https://" + DOMAIN+"/"
            )
        except jwt.ExpiredSignatureError:
            raise AuthError({"code": "token_expired",
                            "description": "token is expired"}, 401)
        except jwt.JWTClaimsError:
            raise AuthError({"code": "invalid_claims",
                            "description":
                                "incorrect claims,"
                                " please check the audience and issuer"}, 401)
        except Exception:
            raise AuthError({"code": "invalid_header",
                            "description":
                                "Unable to parse authentication"
                                " token."}, 401)

        return payload
    else:
        raise AuthError({"code": "no_rsa_key",
                         "description":
                         "No RSA key in JWKS"}, 401)


@app.route('/')
def index():
    return "Please navigate to /Users to use this API"


# Decode the JWT supplied in the Authorization header
@app.route('/decode', methods=['GET'])
def decode_jwt():
    payload = verify_jwt(request)
    return payload


# 1. User Login
@app.route('/' + USERS + '/login', methods=['POST'])
def login_user():

    # Validate request body
    content = request.get_json()
    if len(content) != 2:
        return BAD_REQUEST, 400

    if 'username' in content and 'password' in content:
        username = content["username"]
        password = content["password"]
    else:
        return BAD_REQUEST, 400

    # Generate JWT
    body = {
        'grant_type': 'password',
        'username': username,
        'password': password,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET
    }
    headers = {'content-type': 'application/json'}
    url = 'https://' + DOMAIN + '/oauth/token'
    response = requests.post(url, json=body, headers=headers)

    # Validate response
    if response.status_code == 403:     # Citation #2
        return UNAUTHORIZED, 401

    # Return token
    data = response.json()  # Citation #3
    token = data.get('id_token')
    if token is None:
        return UNAUTHORIZED, 401
    return jsonify({'token': token}), 200


# 2. Get all users
@app.route('/' + USERS, methods=['GET'])
def get_all_users():

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())

        # If sub not in database
        if len(results) != 1:
            return NO_PERMISSION, 403

        # Check if admin
        user = results[0]
        if user['role'] != 'admin':
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Fetch all users
    query = client.query(kind=USERS)
    results = list(query.fetch())

    # Format JSON
    all_users = []
    for user in results:
        formatted_user = {}
        formatted_user['id'] = user.key.id
        formatted_user['role'] = user['role']
        formatted_user['sub'] = user['sub']
        all_users.append(formatted_user)

    return all_users


# 3. Get a user
@app.route('/' + USERS + '/<int:user_id>', methods=['GET'])
def get_a_user(user_id):

    URL = request.host_url

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Get users
        query = client.query(kind=USERS)
        results = list(query.fetch())

        # Determine if JWT is user or admin
        validated = False
        for user in results:
            curr_id = user.key.id
            curr_sub = user['sub']
            if curr_id == user_id and curr_sub == sub:
                validated = True
            elif user['role'] == 'admin' and curr_sub == sub:
                validated = True

        if validated is False:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Get user
    user_key = client.key(USERS, user_id)
    user = client.get(key=user_key)

    # Format JSON
    formatted_user = {}
    id = user.key.id
    formatted_user['id'] = id
    formatted_user['role'] = user['role']
    formatted_user['sub'] = user['sub']

    # If user has avatar
    if user.get('avatar_url'):
        avatar_url = URL + USERS + '/' + str(user_id) + '/avatar'
        formatted_user['avatar_url'] = avatar_url

    # Include courses in return value
    courses = []
    if user['role'] == 'instructor' or user['role'] == 'student':

        query = client.query(kind=COURSES)
        results = list(query.fetch())

        if user['role'] == 'instructor':
            for course in results:
                if id == course['instructor_id']:
                    courses.append(course.key.id)

        elif user['role'] == 'student':
            for course in results:
                if id in course['enrollment']:
                    courses.append(course.key.id)

        formatted_user['courses'] = courses

    return formatted_user


# 4. Create/update a user's avatar
@app.route('/' + USERS + '/<int:user_id>' + '/avatar', methods=['POST'])
def add_avatar(user_id):

    URL = request.host_url

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Validate user-only
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return NOT_FOUND, 403
        elif user['sub'] != sub:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Get file
    if 'file' not in request.files:
        return BAD_REQUEST, 400
    file_obj = request.files['file']

    # Connect to Google Storage
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)

    # Convert file to blob and upload
    blob = bucket.blob(str(user_id))
    file_obj.seek(0)
    blob.upload_from_file(file_obj)

    # Add avatar_url property for user
    user['avatar_url'] = True
    client.put(user)    # Citation #4

    # Format and return JSON
    avatar_url = URL + USERS + '/' + str(user_id) + '/avatar'
    return ({'avatar_url': avatar_url}, 200)


# 5. Get a user’s avatar
@app.route('/' + USERS + '/<int:user_id>' + '/avatar', methods=['GET'])
def get_avatar(user_id):

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Validate user-only
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return NOT_FOUND, 403
        elif user['sub'] != sub:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Connect to Google Storage
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)

    # Locate file
    file_name = str(user_id)
    blob = bucket.blob(file_name)
    if not storage.Blob(bucket=bucket,
                        name=file_name).exists(storage_client):  # Citation #5

        # If no avatar
        user['avatar_url'] = False
        client.put(user)
        return NOT_FOUND, 404

    # Store file
    file_obj = io.BytesIO()
    blob.download_to_file(file_obj)
    file_obj.seek(0)

    return send_file(file_obj, mimetype='image/png',
                     download_name='avatar'), 200


# 6. Delete a user’s avatar
@app.route('/' + USERS + '/<int:user_id>' + '/avatar', methods=['DELETE'])
def delete_avatar(user_id):

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Validate user-only
        user_key = client.key(USERS, user_id)
        user = client.get(key=user_key)
        if user is None:
            return NOT_FOUND, 403
        elif user['sub'] != sub:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Update user info
    user['avatar_url'] = False
    client.put(user)

    # Connect to Google Storage
    storage_client = storage.Client()
    bucket = storage_client.get_bucket(PHOTO_BUCKET)

    # Locate file
    file_name = str(user_id)
    blob = bucket.blob(file_name)
    if not storage.Blob(bucket=bucket,
                        name=file_name).exists(storage_client):

        # If no avatar
        return NOT_FOUND, 404

    # Delete file
    blob.delete()
    return '', 204


# 7. Create a course
@app.route('/' + COURSES, methods=['POST'])
def create_course():

    URL = request.host_url

    # Validate user is admin
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())

        # If sub not in database
        if len(results) != 1:
            return NO_PERMISSION, 403

        # Check if admin
        user = results[0]
        if user['role'] != 'admin':
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Validate request body
    content = request.get_json()
    if len(content) != 5:
        return BAD_REQUEST, 400

    elif not content.get('instructor_id'):
        return BAD_REQUEST, 400

    # Validate instructor
    instructor_id = content['instructor_id']
    user_key = client.key(USERS, instructor_id)
    user = client.get(key=user_key)
    if user is None or user['role'] != 'instructor':
        return BAD_REQUEST, 400

    # Add course
    new_course = datastore.Entity(key=client.key(COURSES))
    new_course.update(
        {
            "subject": content['subject'],
            "number": content['number'],
            "title": content['title'],
            "term": content['term'],
            "instructor_id": content['instructor_id'],
            "enrollment": []
        }
    )
    client.put(new_course)

    # Format JSON response
    return_dict = {}
    id = new_course.key.id
    return_dict['id'] = id
    return_dict['instructor_id'] = new_course['instructor_id']
    return_dict['number'] = new_course['number']
    return_dict['self'] = URL + COURSES + '/' + str(id)
    return_dict['subject'] = new_course['subject']
    return_dict['term'] = new_course['term']
    return_dict['title'] = new_course['title']

    return return_dict, 201


# 8. Get all courses
@app.route('/' + COURSES, methods=['GET'])
def get_all_courses():

    URL = request.host_url

    limit = request.args.get('limit')
    if limit is None:
        limit = PAGE_LIMIT

    offset = request.args.get('offset')
    if offset is None:
        offset = OFFSET

    # Setup query
    query = client.query(kind=COURSES)
    query.order = ['subject']

    # Include pagination
    if offset is None:
        r_iterator = query.fetch(limit=int(limit))
        pages = r_iterator.pages
        results = list(next(pages))

    # Include pagination + offset
    else:
        r_iterator = query.fetch(limit=int(limit), offset=int(offset))
        pages = r_iterator.pages
        results = list(next(pages))

    # Format course list
    course_list = []
    for r in results:
        course = {}
        id = r.key.id
        course['id'] = id
        course['instructor_id'] = r['instructor_id']
        course['number'] = r['number']
        course['self'] = URL + COURSES + '/' + str(id)
        course['subject'] = r['subject']
        course['term'] = r['term']
        course['title'] = r['title']
        course_list.append(course)

    # Format return dictionary
    return_dict = {}
    new_offset = int(offset) + PAGE_LIMIT
    return_dict['courses'] = course_list

    # Include 'next' if not last page
    if r_iterator.next_page_token is not None:
        return_dict['next'] = (URL + COURSES +
                               '?' + 'limit=' + str(PAGE_LIMIT) +
                               '&' + 'offset=' + str(new_offset))

    return return_dict


# 9. Get a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['GET'])
def get_course(course_id):

    URL = request.host_url

    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if course is None:
        return NOT_FOUND, 404

    # Format JSON response
    return_dict = {}
    id = course.key.id
    return_dict['id'] = id
    return_dict['instructor_id'] = course['instructor_id']
    return_dict['number'] = course['number']
    return_dict['self'] = URL + COURSES + '/' + str(id)
    return_dict['subject'] = course['subject']
    return_dict['term'] = course['term']
    return_dict['title'] = course['title']

    return return_dict, 200


# 10. Update a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['PATCH'])
def update_course(course_id):

    URL = request.host_url

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())

        # If sub not in database
        if len(results) != 1:
            return NO_PERMISSION, 403

        # Check if admin
        user = results[0]
        if user['role'] != 'admin':
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Validate course exists
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if course is None:
        return NO_PERMISSION, 403

    # Format course
    return_dict = {}
    id = course.key.id
    return_dict['id'] = id
    return_dict['instructor_id'] = course['instructor_id']
    return_dict['number'] = course['number']
    return_dict['self'] = URL + COURSES + '/' + str(id)
    return_dict['subject'] = course['subject']
    return_dict['term'] = course['term']
    return_dict['title'] = course['title']

    # Get requested updates
    content = request.get_json()
    if len(content) == 0:
        return return_dict, 200

    # Update course values
    for key, value in content.items():

        # Ensure instructor exists.
        if key == 'instructor_id':
            user_key = client.key(USERS, int(value))
            user = client.get(key=user_key)
            if user is None or user['role'] != 'instructor':
                return BAD_REQUEST, 400

        course[key] = value
        return_dict[key] = value
    client.put(course)

    return return_dict


# 11 Delete a course
@app.route('/' + COURSES + '/<int:course_id>', methods=['DELETE'])
def delete_course(course_id):

    # Validate user
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())

        # If sub not in database
        if len(results) != 1:
            return NO_PERMISSION, 403

        # Check if admin
        user = results[0]
        if user['role'] != 'admin':
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Locate course
    course_key = client.key(COURSES, course_id)
    course = client.get(key=course_key)
    if course is None:
        return NO_PERMISSION, 403

    client.delete(course_key)
    return "", 204


# 12 Update enrollment in a course
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['PATCH'])
def update_enrollment(course_id):

    # Validate user is admin or instructor
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())
        user = results[0]

        # If sub not in database
        if len(results) != 1:
            return UNAUTHORIZED, 401

        # Get course info
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return NO_PERMISSION, 403
        course_instructor = course['instructor_id']

        # Check if admin or instructor
        if user['role'] != 'admin' and user.key.id != course_instructor:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # Get requested enrollment updates
    content = request.get_json()
    add_list = content['add']
    remove_list = content['remove']

    # Fetch all users
    query = client.query(kind=USERS)
    query.add_filter('role', '=', 'student')
    students = list(query.fetch())

    # Get user IDs for students
    student_ids = set()
    for student in students:
        id = student.key.id
        student_ids.add(id)

    # Validate updates
    for user_id in add_list:
        if user_id in remove_list or user_id not in student_ids:
            return INVALID_ENROLLMENT, 409

    for user_id in remove_list:
        if user_id in add_list or user_id not in student_ids:
            return INVALID_ENROLLMENT, 409

    # Enroll students in course
    enrollment = course.get('enrollment', [])
    for student in add_list:
        if student not in enrollment:
            enrollment.append(student)

    # Remove students from course
    for student in remove_list:
        if student in enrollment:
            enrollment.remove(student)

    # Save updates
    client.put(course)
    return "", 200


# 13. Get enrollment for a course
@app.route('/' + COURSES + '/<int:course_id>' + '/students', methods=['GET'])
def get_enrollment(course_id):

    # Validate user is admin or instructor
    try:

        # Get JWT
        payload = verify_jwt(request)
        sub = dict(payload)['sub']

        # Find user
        query = client.query(kind=USERS)
        query.add_filter('sub', '=', sub)
        results = list(query.fetch())
        user = results[0]

        # If sub not in database
        if len(results) != 1:
            return UNAUTHORIZED, 401

        # Get course info
        course_key = client.key(COURSES, course_id)
        course = client.get(key=course_key)
        if course is None:
            return NO_PERMISSION, 403
        course_instructor = course['instructor_id']

        # Check if admin or instructor
        if user['role'] != 'admin' and user.key.id != course_instructor:
            return NO_PERMISSION, 403

    # JWT is missing of invalid
    except AuthError:
        return UNAUTHORIZED, 401

    # return enrollment
    enrollment = course.get('enrollment', [])
    return enrollment, 200


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)
