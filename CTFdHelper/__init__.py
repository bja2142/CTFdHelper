from requests import Session as requests_session

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

class CTFdHelper:

    def __init__(self,url_base,username="admin", password="password123", initial_data = ctf_initial_data):
        self.url_base = url_base
        self.password = password
        self.username = username
        self.session = requests_session()
        self.api_token = None
        self.csrf_nonce = None
        self.initial_data = initial_data
        self.establish_session()

    def get(self, url, **args):
        return self.session.get(self.url_base + url, **args)

    def post(self, url, **args):
        return self.session.post(self.url_base + url, **args)

    def api_post(self, url, **args):
        return self.post('/api/v1' + url, **args)

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
        resp = self.get('/setup')
        if "SetupForm" in resp.text:
            nonce = self.get_nonce(resp.text)
            self.initialize_ctf(nonce)
        else:
            self.login()
        self.get_csrf()
        self.prep_api()

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
