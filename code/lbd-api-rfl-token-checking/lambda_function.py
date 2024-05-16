"""
capas:
capa-requests-cryptography-pyjwt-3-9

ram:
1024MB

"""

import jwt
import logging
import sys
import os
from precia_utils import get_secret
from decorators import handler_wrapper, debugger_wrapper


logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    lo = lambda_object(event)
    return lo.starter()


class lambda_object:
    def __init__(self, event):
        try:
            self.failed_init = False
            self.final_response = {
                "principalId": "user",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [
                        {
                            "Action": "execute-api:Invoke",
                            "Effect": "Deny",
                            "Resource": str(),
                        }
                    ],
                },
            }
            self.detailed_raise = ""
            self.partial_response = {}
            self.token = event["authorizationToken"]
            self.final_response["policyDocument"]["Statement"][0]["Resource"] = event[
                "methodArn"
            ]
        except (Exception,) as e:
            logger.error(
                "[__init__] Error inicializando objeto lambda, linea: %s, motivo: %s",
                get_current_error_line(),
                e,
            )
            self.failed_init = True

    def starter(self):
        try:
            if self.failed_init:
                raise AttributeError("Error con los datos recibidos al servicio")
            self.get_secret_information()
            self.check_token()

            return self.response_maker()
        except (Exception,):
            logger.error(
                "[starter] Hubieron problemas en el comando de la linea: %s",
                get_current_error_line(),
            )
            return self.response_maker()

    @handler_wrapper(
        "Obteniendo secretos",
        "Secretos obtenidos con exito",
        "Error obteniendo secretos",
        "Error descifrando información empresarial",
    )
    def get_secret_information(self):
        secret_autentication_info = os.environ["SECRET_AUTENTICATION_INFO"]
        autenticacion_info = get_secret(secret_autentication_info)
        self.ms_tenant = autenticacion_info["ms_tenant"]
        self.client_id = autenticacion_info["client_id"]

    @handler_wrapper(
        "Chequeando token",
        "Token chequeado, generando respuesta",
        "Error chequeando token",
        "Error chequeando token",
    )
    def check_token(self):
        key_url = "https://login.microsoftonline.com/common/discovery/keys"
        jwks_client = jwt.PyJWKClient(key_url)
        signing_key = jwks_client.get_signing_key_from_jwt(self.token)
        jwt.decode(
            self.token,
            signing_key.key,
            algorithms=["RS256"],
            audience=self.client_id
        )
        self.final_response["policyDocument"]["Statement"][0]["Effect"] = "Allow"

    @debugger_wrapper(
        "Error construyendo respuesta final", "Error construyendo respuesta"
    )
    def response_maker(self):
        return self.final_response


def get_current_error_line():
    return str(sys.exc_info()[-1].tb_lineno)
