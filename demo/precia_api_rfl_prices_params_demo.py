"""
Demo API Precia RFL Precios: Configuracion/parametrizacion de la consulta

Este script:
- Se autentica para obtener los tokens de autorización y autenticacion.
- Ingresa a la ruta /config/rfl/prices para parametrizar la consulta antes de la ejecución
  del proceso de valoracion
"""

from json import load as json_load
import logging
from sys import stdout

import requests

CONFIG_FILE = "config.json"
DATA_REQUEST_FILE = "data_request.json"
AUTH_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
PARAM_SLUG = "/config/rfl/prices"

logger = logging.getLogger()
logger.setLevel(logging.INFO)
format = logging.Formatter(
    "%(asctime)s [%(levelname)s] [%(filename)s](%(funcName)s): %(message)s"
)
ch = logging.StreamHandler(stdout)
ch.setFormatter(format)
logger.addHandler(ch)


def get_tokens(url, client_id, username, password, client_secret):
    """
    Realiza solicitud a la API para autenticarse y obtener tokens para consultar datos
    """
    logger.info("Obteniendo tokens en %s ...", url)
    payload = {
        "client_id": client_id,
        "grant_type": "password",
        "scope": "openid",
        "username": username,
        "password": password,
        "client_secret": client_secret,
    }
    response = requests.post(url, data=payload)
    if response.status_code != 200:
        logger.error(
            "Error al obtener los tokens. Respuesta del servidor: %s", response.text
        )
        response.raise_for_status()
    logger.info("Tokens obtenidos existosamente.")
    return response.json()


def set_data_request_params(url, tokens, params):
    """
    Realiza solicitud a la API para parametrizar consulta de isines y campos
    """
    logger.info("Parametrizando consulta de RFL Precios en %s ...", url)
    headers = {"Authorization": tokens["id_token"], "Authentication": tokens["access_token"]}
    response = requests.post(url, json=params, headers=headers)
    if response.status_code != 200:
        logger.error(
            "Error al parametrizar la consulta. Respuesta del servidor: %s",
            response.text,
        )
        response.raise_for_status()
    logger.info(
        "Parametrizacion exitosa. Respuesta del servidor: %s", response.text)

def main():
    """
    Funcion principal de la demo
    """
    logger.info("Cargando variables de entorno del archivo %s ...", CONFIG_FILE)
    config = json_load(open(CONFIG_FILE))
    logger.info("Archivo de configuracion cargado.")
    auth_url = AUTH_URL.format(tenant_id=config["tenant_id"])
    tokens = get_tokens(
        auth_url,
        config["client_id"],
        config["username"],
        config["password"],
        config["client_secret"],
    )
    param_url = config["precia_api_url"] + PARAM_SLUG
    logger.info(
        "Cargando isines y campos a consultar del archivo %s ...", DATA_REQUEST_FILE
    )
    data_params = json_load(open(DATA_REQUEST_FILE))
    logger.info("Archivo de parametros de la consulta cargado.")
    set_data_request_params(param_url, tokens, data_params["payload_request"])
if __name__ == "__main__":
    main()
