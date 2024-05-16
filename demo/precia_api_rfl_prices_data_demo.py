from json import load as json_load, dumps as json_dumps
import logging
from sys import stdout

import requests

CONFIG_FILE = "config.json"
DATA_REQUEST_FILE = "data_request.json"
AUTH_URL = "https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token"
DATA_SLUG = "/rfl/prices"

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


def get_price_data_url(url, tokens, valuation_date=None, all_isines=False):
    """
    Obtiene la url con los datos y metadatos de los precios RFL fin de dia
    """
    request = requests.models.PreparedRequest()
    if valuation_date is not None:
        request.prepare_url(url, {"valuation-date": valuation_date})
        url = request.url
    if all_isines:
        request.prepare_url(url, {"isines": "all"})
        url = request.url
    logger.info("Obteniendo los RFL Precios en %s ...", url)
    headers = {
        "Authorization": tokens["id_token"],
        "Authentication": tokens["access_token"],
    }
    response = requests.get(url, headers=headers)
    if response.status_code != 200:
        logger.error(
            "Error al realizar la consulta. Respuesta del servidor: %s : %s",
            response.status_code,
            response.text,
        )
        return None
    logger.info("Consulta existosa. Respuesta del servidor: %s",
                json_dumps(response.json(), indent=4))
    return response.json()["data_url"]

def get_data_like_file(url, filename):
    """
    Descarga los datos como archivos
    """
    logger.info("Descargando datos para el archivo %s ...", filename)
    if url is None:
        logger.warning("No se pudo crear el archivo %s porque no hay datos disponibles", filename)
    else:
        response = requests.get(url)
        if response.status_code != 200:
            logger.error(
                "Error al realiza la descarga de datos. Respuesta del servidor: %s : %s",
                response.status_code,
                response.text,
            )
            raise FileExistsError("No fue posible descargar los datos como archivo %s", filename)
        with open(filename, "w") as data_file:
            data_file.write(response.text)
        logger.info("Archivo %s creado", filename)
    

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
    data_url = config["precia_api_url"] + DATA_SLUG
    logger.info(
        "Cargando isines y campos a consultar del archivo %s ...", DATA_REQUEST_FILE
    )
    data_params = json_load(open(DATA_REQUEST_FILE))
    logger.info("Archivo de parametros de la consulta cargado.")
    logger.info("Consultando precios parametrizados para hoy ...")
    today_data_url = get_price_data_url(data_url, tokens)
    get_data_like_file(today_data_url, "rfl_price_data_today.json")
    valuation_date = data_params["query_params"]["valuation_date"]
    logger.info(
        "Consultando precios parametrizados para la fecha %s ...", valuation_date
    )
    data_by_date_url = get_price_data_url(
        data_url, tokens, valuation_date=valuation_date
    )
    get_data_like_file(data_by_date_url, f"rfl_price_data_{valuation_date}.json")
    logger.info(
        "Consultando precios de todos los isines para la fecha %s ...", valuation_date
    )
    all_isines_data_url = get_price_data_url(
        data_url, tokens, valuation_date=valuation_date, all_isines=True
    )
    get_data_like_file(all_isines_data_url, f"rfl_price_all_isines_{valuation_date}.json")


if __name__ == "__main__":
    main()
