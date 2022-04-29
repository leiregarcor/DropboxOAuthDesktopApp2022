import requests
import urllib
import webbrowser
import socket
import json


app_key = 'ya2ra1avjd5yiug'
app_secret = 'tvejc2pnlh59fr5'
server_addr = 'localhost'
server_port ='8090'
redirect_uri = "http://" + server_addr + ":" + str(server_port)


def local_server():
    print('OAuth 2.0 access tokens lortzen...')
    base_uri = "https://www.dropbox.com/oauth2/authorize"
    goiburuak = {'Host': 'dropbox.com'}
    datuak = {'client_id': app_key,
              'redirect_uri': redirect_uri,  # Dirección IP de bucle invertido
              'response_type': 'code', }

    datuak_kodifikatuta = urllib.parse.urlencode(datuak)  # parametroak URI-an daude
    auth_uri = base_uri + '?' + datuak_kodifikatuta

    print("\n\t Web nabigatzailea irekitzen: Dropbox prompts user for consent")
    webbrowser.open_new(auth_uri)

    print("\n\tHandle the OAuth 2.0 server response")
    # 8090. portuan entzuten dagoen zerbitzaria sortu
    listen_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_socket.bind(('localhost', 8090))
    listen_socket.listen(1)
    print("\t\tSocket listening on port 8090")

    # nabitzailetik 302 eskaera jaso beharko du
    # ondorengo lerroan programa gelditzen da zerbitzariak 302 eskaera jasotzen duen arte
    client_connection, client_address = listen_socket.accept()
    eskaera = client_connection.recv(1024).decode()
    print("\t\tNabigatzailetik ondorengo eskaera jaso da:")
    print("\n" + eskaera)  # zerbitzariak jasotzen duen eskaera

    # eskaeran "auth_code"-a bilatu
    lehenengo_lerroa = eskaera.split('\n')[0]
    aux_auth_code = lehenengo_lerroa.split(' ')[1]
    auth_code = aux_auth_code[7:].split('&')[0]
    print("auth_code: " + auth_code)

    # erabiltzaileari erantzun bat bueltatu
    http_response = """\
    HTTP/1.1 200 OK

    <html>
    <head><title>Proba</title></head>
    <body>
    The authentication flow has completed. Close this window.
    </body>
    </html>
    """
    client_connection.sendall(str.encode(http_response))
    client_connection.close()

    return auth_code


def do_oauth():
    # Authorization
    print("###################################")
    print("OAuth 2.0 for Mobile & Desktop Apps")
    print("###################################")

    print("\nPrerequisites on DropBox")
    print("\tEnable APIs for your project")
    print("\tChoose from different scopes in the ‘Permissions’ tab")
    print("\tCreate authorization credentials")

    auth_code = local_server()

    # Exchange authorization code for access token
    # sartu kodea hemen

    return access_token

'''

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

'''
access_token = do_oauth()
