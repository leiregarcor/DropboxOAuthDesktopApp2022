import requests
import urllib
import webbrowser
import socket
import json


app_key =
app_secret =
server_addr =
server_port =
redirect_uri = "http://" + server_addr + ":" + str(server_port)


def local_server():
    # sartu kodea hemen
    return auth_code


def do_oauth():
    # Authorization
    # sartu kodea hemen

    auth_code = local_server()

    # Exchange authorization code for access token
    # sartu kodea hemen

    return access_token


def list_folder(access_token, cursor="", edukia_json_entries=[]):
    if not cursor:
        print("/list_folder")
        uri =
        datuak =
    else:
        print("/list_folder/continue")
        uri =
        datuak =

    # Call Dropbox API
    # sartu kodea hemen

    # See if there are more entries available. Process data.
    edukia_json = json.loads(edukia)
    if edukia_json['has_more']:
        # sartu kodea hemen


access_token = do_oauth()
list_folder(access_token)