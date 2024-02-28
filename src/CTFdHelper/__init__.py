from requests import Session as requests_session
from requests.exceptions import ConnectionError
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import re
import copy
import json
from datetime import datetime, timedelta
from secrets import token_urlsafe
from mimetypes import guess_type
from pathlib import PosixPath

import re
ctf_initial_data = {
    "ctf_name": ("Event Name Here",),
    "ctf_description": ("Event Description here",),
    "user_mode": ("users",),
    "challenge_visibility": ("private",),
    "account_visibility": ("private",),
    "score_visibility": ("private",),
    "registration_visibility": ("private",),
    "verify_emails": ("false",),
    "team_size": ("",),
    "email": ("admin@localhost.com",),
    "ctf_logo": ("","","application/octet-stream"),
    "ctf_banner": ("","","application/octet-stream"),
    "ctf_small_icon": ("","","application/octet-stream"),
    "ctf_theme": ("core-beta",),
    "theme_color": ("",),
    "start": ("",),
    "end": ("",),
    "_submit": ("Finish",),
}

#https://stackoverflow.com/questions/63974944/posting-multi-part-form-encoded-dict

#https://stackoverflow.com/a/75695201
def dict_to_multipart(dict_data):
    file_data = []
    for key in dict_data.keys():
        value = dict_data[key][0]
        headers = None
        filename = None
        if len(dict_data[key]) >1:
            filename = dict_data[key][1]
        if len(dict_data[key]) >2:
            headers = dict_data[key][2]
        file_data.append((str(key),(filename,str(value),headers)))
        #trial and error: name={0}, filename={1}, Content-Type: {3}, Content:{2}
    return file_data

def file_to_multipart(name, filename, content_type, content, data={}):
    file_data = []
    if content_type:
        headers = content_type
    else:
        headers = None
    filename = filename
    file_data.append((str(name),(filename, content, headers)))
    for key in data.keys():
        value = data[key]
        headers = None
        filename = None
        file_data.append((str(key),(filename,str(value),headers)))
    return file_data

DEFAULT_THEME_SETTINGS = {
  "challenge_window_size": "xl",
  "challenge_category_order": "function compare(a, b) {\r\n  if (a < b) {\r\n    return -1;\r\n  }\r\n  if (a > b) {\r\n    return 1;\r\n  }\r\n  return 0;\r\n}",
  "challenge_order": "function compare(a, b) {\r\n  if (a.value < b.value) {\r\n    return -1;\r\n  }\r\n  if (a.value > b.value) {\r\n    return 1;\r\n  }\r\n  if (a < b) {\r\n    return -1;\r\n  }\r\n  if (a > b) {\r\n    return 1;\r\n  }\r\n  return 0;\r\n}",
  "use_builtin_code_highlighter": True
}

class CTFdHelper:

    def __init__(self,url_base,username="admin", password="password123", initial_data = ctf_initial_data):
        self.url_base = url_base
        self.password = password
        self.username = username
        self.session = requests_session()
        retry = Retry(connect=3, backoff_factor=0.5)
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount('http://', adapter)
        self.session.mount('https://', adapter)
        self.api_token = None
        self.csrf_nonce = None
        self.initial_data = initial_data
        #self.establish_session()

    def get(self, url, **args):
        return self.session.get(self.url_base + url, **args)

    def post(self, url, **args):
        return self.session.post(self.url_base + url, **args)

    def patch(self, url, **args):
        return self.session.patch(self.url_base + url, **args)

    def delete(self, url, **args):
        return self.session.delete(self.url_base + url, **args)

    def api_post(self, url, **args):
        return self.post('/api/v1' + url, **args)

    def api_get(self, url, **args):
        return self.get('/api/v1' + url, **args)

    def api_patch(self, url, **args):
        return self.patch('/api/v1' + url, **args)

    def api_delete(self, url, **args):
        return self.delete('/api/v1' + url, **args)

    def api_post_challenge(self,
                           name, description, connection_info, value, category, chal_type, max_attempts=0, state="visible"):
        blob = {
            "name" : name,
            "description": description,
            "connection_info": connection_info,
            "max_attempts": str(max_attempts),
            "value" : str(value),
            "category": category,
            "type": chal_type,
            "state": state,
        }
        return self.api_post('/challenges', json=blob)

    def api_get_scoreboard(self):
        return self.api_get('/scoreboard').json()["data"]

    def api_get_submissions(self):
        response = self.api_get('/submissions').json()
        pagination = response["meta"]["pagination"]
        pages = pagination["pages"]
        results = []
        for page in range(1,int(pages)+1):
            page_response = self.api_get('/submissions?page='+str(page)).json()
            results += page_response["data"]
        return results

    def get_backup(self):
        response = self.get("/admin/export")
        return response

    def save_backup_to_disk(self,outfile):
        data = self.get_backup()
        f = open(outfile, "wb")
        f.write(data.content)
        f.close()

    def api_post_flag(self, challenge_id, flag_type, content, data=""):
        blob = {
            "challenge_id": challenge_id,
            "type" : flag_type,
            "content" : content,
            "data": data
            }
        return self.api_post('/flags', json=blob)

    def api_post_hint(self, challenge_id, hint_type, content, cost=0, requirements={}):
        blob = {
            "challenge_id": challenge_id,
            "type" : hint_type,
            "content" : content,
            "cost": cost,
            "requirements": requirements
            }
        return self.api_post('/hints', json=blob)

    def api_post_user(self, username, password, email, verified=True):
        blob = {
            "name": username,
            "password" : password,
            "email" : email,
            "verified": verified
            }
        return self.api_post('/users', json=blob)

    def api_post_tag(self, challenge_id, value):
        blob = {
            "challenge_id": challenge_id,
            "value" : value
        }
        return self.api_post('/tags', json=blob)

    def api_post_page(self,
                     route,
                     title=None,
                     content="",
                     draft = False,
                     hidden=None,
                     auth_required=True,
                     format="markdown"):
        blob = {
            "route" : route,
            "content": content,
            "draft" : draft,
            "auth_required" : auth_required,
            "format" : format,
        }
        if title:
            blob["title"] = title
        if hidden != None:
            blob["hidden"] = hidden
        return self.api_post('/pages', json=blob)

    def api_patch_page(self, pageid,
                     route=None,
                     title=None,
                     content=None,
                     draft=None,
                     hidden=None,
                     auth_required=None,
                     format="markdown"):
        blob = {}
        if route != None:
            blob["route"] = route
        if title != None:
            blob["title"] = title
        if content != None:
            blob["content"] = content
        if draft != None:
            blob["draft"] = draft
        if hidden != None:
            blob["hidden"] = hidden
        if auth_required != None:
            blob["auth_required"] = auth_required
        if format != None:
            blob["format"] = format

        return self.api_patch('/pages/{}'.format(pageid), json=blob)
        
    def api_delete_page(self, pageid):
        return self.api_delete('/pages/{}'.format(pageid))

    def api_get_page(self, pageid):
        return self.api_get('/pages/{}'.format(pageid))

    def api_get_pages(self):
        return self.api_get('/pages')
    
    def api_get_config_list(self):
        return self.api_get('/configs')
    
    def api_get_config_key(self, key):
        return self.api_get('/configs/{}'.format(key))
    
    def api_patch_config_key(self, key, value):
        blob = {key : value}
        return self.api_patch('/configs', json=blob)
    
    def api_delete_config(self, key):
        return self.api_delete('/configs/{}'.format(key))
    
    def api_get_config_fields(self):
        return self.api_get('/configs/fields')

    def api_get_config_field(self, field_id):
        return self.api_get('/configs/fields/{}'.format(field_id))

    def api_delete_challenge(self, challengeid):
        return self.api_delete('/challenges/{}'.format(challengeid))

    def set_new_theme(self, themename):
        return self.api_patch_config_key("ctf_theme", themename)

    def pause_ctf(self):
        blob = {
            "paused": True
        }
        return self.api_patch('/configs', json=blob)

    def apply_theme_settings(self, settings=False):
        if not settings:
            settings = DEFAULT_THEME_SETTINGS
        blob = {
            "theme_settings" : json.dumps(settings)
        }
        return self.api_patch('/configs', json=blob)

    def get_challenge_list(self):
        challenges = self.api_get('/challenges')
        challenges_list = challenges.json()["data"]
        return challenges_list

    def hide_all_challenges(self):
        challenges = self.get_challenge_list()
        for challenge in challenges:
            self.hide_challenge(challenge["id"])

    def hide_challenge(self, challenge_id):
        blob = {
            "state": "hidden"
        }
        return self.api_patch('/challenges/{}'.format(challenge_id), json=blob)

    def show_challenge(self, challenge_id):
        blob = {
            "state": "visible"
        }
        return self.api_patch('/challenges/{}'.format(challenge_id), json=blob)

    def upload_challenge_file_from_path(self, challenge_id, path, new_fname = None):
        file = PosixPath(path)
        fname = file.name
        if new_fname:
            fname = new_fname
        content_type = guess_type(file.name)[0]
        if not content_type:
            content_type = "application/octet-stream"
        data = file.read_bytes()
        return self.upload_challenge_file(challenge_id, fname, data, content_type)
    
    def upload_challenge_file(self, challenge_id, fname, content, content_type):
        challenge_info = {
            "nonce": self.csrf_nonce,
            "challenge": str(challenge_id),
            "type": "challenge"
        }
        data = file_to_multipart("file", fname, content_type, content, challenge_info)
        resp = self.api_post('/files', files=data)
        return resp

    def unpause_ctf(self):
        blob = {
            "paused": False
        }
        return self.api_patch('/configs', json=blob)

    def prep_api(self, force=False):
        if self.api_token == None or force:
            self.get_api_token()
            self.session.headers.update({'Authorization': 'Token ' + self.api_token})

    def get_csrf(self, force=False):
        if self.csrf_nonce == None or force:
            text = self.get('/settings').text
            self.csrf_nonce = self.get_csrf_nonce(text)
            self.session.headers.update({"Csrf-Token" : self.csrf_nonce})
        return self.csrf_nonce

    def get_api_token(self):
        expiration = (datetime.today()+ timedelta(hours=48)).strftime("%Y-%m-%d")
        result = self.post('/api/v1/tokens',
                  json={
                    "expiration": expiration,
                    "description": "API Token for CTFdHelper"
                  }
            )
        self.api_token = result.json()['data']['value']

    def establish_session(self):
        try:
            resp = self.get('/setup')
            response_text = resp.text
        except ConnectionError as e:
            response_text = ""
        if "SetupForm" in response_text:
            nonce = self.get_nonce(response_text)
            self.initialize_ctf(nonce)
        else:
            self.login()
        self.get_csrf()
        self.prep_api()

    def remove_all_pages(self):
        response = self.api_get_pages().json()
        pages = response["data"]
        for page in pages:
            self.api_delete_page(page["id"])
        
        

    def login(self):
        resp = self.get('/login')
        nonce = self.get_nonce(resp.text)
        form_data = {
            "name" : (self.username,),
            "password" : (self.password,),
            "nonce" : (nonce,),
            "_submit": ("Submit",)
        }
        form_data = dict_to_multipart(form_data)
        resp = self.post('/login', files=form_data)
        return resp

    def create_user(self,username, password):
        resp = self.api_post_user(username, password, username+"@example.com")
        return resp


    def get_nonce(self,pagetext):
        nonce = re.findall('.*name="nonce"[^>]*value="([^"]*)".*', pagetext)
        if len(nonce) == 0:
            raise Exception('Could not find nonce. Is the CTFd instance actually running?')
        nonce = nonce[0]
        return nonce

    def get_csrf_nonce(self,pagetext):
        nonce = re.findall('.*\'csrfNonce\': "([^"]*)",', pagetext)
        if len(nonce) == 0:
            raise Exception('Could not find CSRF nonce')
        nonce = nonce[0]
        return nonce

    def initialize_ctf(self,nonce):
        instance_data = self.initial_data
        resp = self.get('/setup')
        nonce = self.get_nonce(resp.text)
        instance_data['nonce'] = (nonce,)
        instance_data['password'] = (self.password,)
        instance_data['name'] = (self.username,)
        file_data = dict_to_multipart(instance_data)
        resp = self.post('/setup', files=file_data)
