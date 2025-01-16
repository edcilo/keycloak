import json
from fastapi import FastAPI, Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth
from onelogin.saml2.utils import OneLogin_Saml2_Utils

app = FastAPI()

async def prepare_request_data(request: Request):
    url_scheme = request.scope.get("scheme", "http")
    host = request.client.host
    port = request.scope.get("server")[1]
    script_name = request.url.path

    return {
        "https": "on" if url_scheme == "https" else "off",
        "http_host": host,
        "server_port": str(port),
        "script_name": script_name,
        "get_data": request.query_params,
        "post_data": await request.form()
    }

async def init_saml_auth(request: Request):
    settings_file_path = './saml_settings.json'
    with open(settings_file_path) as f:
        saml_settings = json.load(f)
    request_data = await prepare_request_data(request)
    return OneLogin_Saml2_Auth(request_data, saml_settings)

# saml routes
@app.get("/metadata")
async def metadata(request: Request):
    saml_auth = await init_saml_auth(request)
    settings = saml_auth.get_settings()
    metadata = settings.get_sp_metadata()
    errors = settings.validate_metadata(metadata)
    if len(errors) > 0:
        raise ValueError('Invalid SP metadata: %s' % (', '.join(errors)))
    return metadata

@app.post("/saml/acs")
async def saml_acs(request: Request):
    print(request)
    saml_auth = await init_saml_auth(request)
    saml_auth.process_response()
    errors = saml_auth.get_errors()
    if len(errors) > 0:
        raise ValueError('Error when processing SAML Response: %s' % (', '.join(errors)))
    if saml_auth.is_authenticated():
        user_data = saml_auth.get_attributes()
        return {"message": "User authenticated", "user_data": user_data}
    return {"message": "User not authenticated"}

@app.post("/saml/sls")
async def saml_sls(request: Request):
    saml_auth = await init_saml_auth(request)
    saml_auth.process_slo(delete_session_cb=lambda: None)
    errors = saml_auth.get_errors()
    if len(errors) > 0:
        raise ValueError('Error when processing SAML Response: %s' % (', '.join(errors)))
    return {"message": "User logged out"}

@app.get("/saml/login")
async def saml_login(request: Request):
    saml_auth = await init_saml_auth(request)
    return {
        "login-url": saml_auth.login()
    }

@app.get("/saml/logout")
async def saml_logout(request: Request):
    saml_auth = await init_saml_auth(request)
    return saml_auth.logout()

# app routes
@app.get("/")
def home():
    return {"message": "Hello World"}
