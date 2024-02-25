import binascii
import os
import traceback

from flask import Flask, request, url_for, make_response, abort
from .DatabaseConnection import DatabaseConnection
from .ExpiringDictionary import ExpiringDictionary
# TODO: Abstract into Microservices, then import into main app

app = Flask("__name__")
PREFIX = "/api/v1"
connection = DatabaseConnection()

tokens = ExpiringDictionary()

# ----- Error Handling -----
# app.register_error_handler(AuthenticationFailedException)
# app.register_error_handler(UserNotFoundException)
# app.register_error_handler(SongNotFoundException)

# ----- Users -----
@app.route(f"{PREFIX}/user/login")
def user_login():
    try:
        return connection.create_session(request.args.get("username"), request.args.get("password"))
    # except Exceptions.Database.AuthenticationFailedException:
    #     raise AuthenticationFailedException
    except: abort(500)

@app.route(f"{PREFIX}/user/register")
def user_register():
    try:
        resp = make_response()
        resp.set_cookie("token", connection.create_user(request.args.get("username"), request.args.get("password"), request.args.get("is_teacher", type=bool)))
        return resp
    # except Exceptions.Database.UnavailableUsernameException:
    #     raise UnavailableUsernameException
    # except ValueError:
    #     abort(400)
    except Exception as e:
        traceback.print_exc()
        abort(500)


@app.route(f"{PREFIX}/user/logout")
def user_logout():
    try:
        connection.delete_session(request.cookies.get("token"))
        abort(200)
    # except Exceptions.Database.InvalidSessionException:
    #     raise InvalidSessionException
    except: abort(500)

@app.route(f"{PREFIX}/user/delete")
def user_delete():
    try:
        connection.delete_user(request.args.get("username"), request.args.get("password"), request.args.get("token"))
        abort(200)
    # except Exceptions.Database.InvalidSessionException:
    #     raise InvalidSessionException
    # except Exceptions.Database.AuthenticationFailedException:
    #     raise AuthenticationFailedException
    except: abort(500)

@app.route(f"{PREFIX}/user/role")
def user_role():
    try:
        return "Student" if connection.is_teacher(request.cookies.get("token")) else "Teacher"
    # except Exceptions.Database.InvalidSessionException:
    #     raise InvalidSessionException
    except: abort(500)

@app.route(f"{PREFIX}/user/authenticate")
def user_authenticate():
    try:
        connection.check_token(request.cookies.get("token"))
        return True
    except: return False

@app.route(f"{PREFIX}/user/change/password")
def user_update_password():
    try:
        connection.change_password(request.args.get("password"), request.args.get("new_password"), request.cookies.get("token"))
        abort(200)
    # except Exceptions.Database.InvalidSessionException:
    #     raise InvalidSessionException
    except: abort(500)


@app.route(f"{PREFIX}/user/change/username")
def user_update_username():
    try:
        connection.change_username(request.args.get("password"), request.args.get("new_username"), request.cookies.get("token"))
        abort(200)
    # except Exceptions.Database.InvalidSessionException:
    #     raise InvalidSessionException
    except: abort(500)

# TODO: Return correct exception
# ----- Songs -----
@app.route(f"{PREFIX}/song/upload")
def song_upload():
    try:
        connection.create_song(request.args.get("song_name"), request.args.get("song"), request.cookies.get("token"))
        abort(201)
    except: abort(500)

@app.route(f"{PREFIX}/song/edit")
def song_edit():
    try:
        connection.update_song(request.args.get("song_id", type=int), request.args.get("song_name"), request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/song/delete/<song_id>")
def song_delete(song_id: int):
    try:
        connection.delete_song(song_id, request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/song/delete_all")
def song_delete_all():
    try:
        connection.delete_all_songs(request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/song/fetch_all")
def song_fetch_all():
    try:
        return connection.fetch_available_songs(request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/song/fetch_name/<song_id>")
def song_fetch_name(song_id: int):
    try:
        return connection.fetch_song_name(song_id, request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/song/fetch_song/<song_id>")
def song_fetch(song_id: int):
    try:
        return connection.fetch_song(song_id, request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/song/fetch_owned")
def song_fetch_owned():
    try:
        return connection.fetch_owned_songs(request.cookies.get("token"))
    except: abort(500)

# ---- Students -----
@app.route(f"{PREFIX}/students/generate_tokens")
def students_generate_tokens():
    try:
        token = binascii.hexlify(os.urandom(20)).decode()
        while token in tokens.keys(): token = binascii.hexlify(os.urandom(20)).decode()
        tokens[token] = connection.get_user_id(connection.get_session_username(request.cookies.get("token")))
        return token
    except: abort(500)

@app.route(f"{PREFIX}/students/remove/<student_id>")
def students_remove(student_id: int):
    try:
        connection.remove_student(student_id, request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/students/remove_all")
def students_remove_all():
    try:
        connection.remove_all_students(request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/students/fetch_name/<student_id>")
def students_fetch_name(student_id: int):
    try:
        return connection.fetch_student_name(student_id, request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/students/fetch_all")
def students_fetch_all():
    try:
        return connection.fetch_all_students(request.cookies.get("token"))
    except: abort(500)

# ---- teacher -----
@app.route(f"{PREFIX}/teacher/join/<join_token>")
def teacher_join(join_token: str):
    try:
        teacher_id = tokens.get(join_token)
        connection.join_teacher(teacher_id, request.cookies.get("token"))
        abort(201)
    except: abort(500)

@app.route(f"{PREFIX}/teacher/leave")
def teacher_leave():
    try:
        connection.leave_teacher(request.cookies.get("token"))
        abort(200)
    except: abort(500)

# ----- Shares -----
@app.route(f"{PREFIX}/share/add")
def share_add():
    try:
        connection.add_share(request.args.get("student_id", type=int), request.args.get("song_id", type=int), request.cookies.get("token"))
        abort(201)
    except: abort(500)

@app.route(f"{PREFIX}/share/revoke")
def share_revoke():
    try:
        connection.revoke_share(request.args.get("student_id", type=int), request.args.get("song_id", type=int), request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/share/fetch_all")
def share_fetch_all():
    try:
        return connection.fetch_shares(request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/share/fetch_by_student/<student_id>")
def share_fetch_student(student_id: int):
    try:
        return connection.fetch_shares_by_student(student_id, request.cookies.get("token"))
    except: abort(500)

@app.route(f"{PREFIX}/share/fetch_by_song/<song_id>")
def share_fetch_song(song_id: int):
    try:
        return connection.fetch_shares_by_song(song_id, request.cookies.get("token"))
    except: abort(500)
@app.route(f"{PREFIX}/share/revoke_all/student/<student_id>")
def share_revoke_all_student(student_id: int):
    try:
        connection.revoke_by_student(student_id, request.cookies.get("token"))
        abort(200)
    except: abort(500)

@app.route(f"{PREFIX}/share/revoke_all/song/<song_id>")
def share_revoke_all_song(song_id: int):
    try:
        connection.revoke_by_song(song_id, request.cookies.get("token"))
        abort(200)
    except: abort(500)