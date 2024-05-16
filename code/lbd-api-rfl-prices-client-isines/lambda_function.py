"""
Lambda: Obtención de ISINES de clientes en DynamoDB 
Esta lambda se encarga de generar un url firmado con tiempo de vida de 15 minutos de un archivo 
alojado en un Bucket s3 según la versión de los datos y el cliente que lo solicita
"""

from base64 import urlsafe_b64decode
from datetime import datetime as dt
from decimal import Decimal
import json
import logging
import os
from sys import exc_info, stdout

import boto3
from boto3.dynamodb.conditions import Key

VERSION_TABLE_NAME = os.environ["VERSION_TABLE_NAME"]
CLIENTS_PARAMS_TABLE_NAME = os.environ["CLIENTS_PARAMS_TABLE_NAME"]
EXPIRATE_SEC_TIME = os.environ["EXPIRATE_SEC_TIME"]
S3_CLIENT = boto3.client("s3")
OUTPUT_BUCKET_NAME = os.environ["OUTPUT_BUCKET_NAME"]
OUTPUT_BUCKET_URL = os.environ["OUTPUT_BUCKET_URL"]
CLOUDFRONT_URL = os.environ["CLOUDFRONT_URL"]
OUTPUT_FILE_PATH = os.environ["OUTPUT_FILE_PATH"]
DYNAMODB_RESOURCE = boto3.resource("dynamodb")
GENERIC_API_USER = "all_isines"
GENERIC_CONTEXT = "Renta Fija Local; Precios; Fin de dia {valuation_date}"


def setup_logging(log_level):
    """
    Configura el sistema de registro de logs.
    """
    precia_log_format = (
        "%(asctime)s [%(levelname)s] [%(filename)s](%(funcName)s): %(message)s"
    )

    loggers = logging.getLogger()
    for handler in loggers.handlers:
        loggers.removeHandler(handler)
        file_handler = logging.StreamHandler(stdout)
    file_handler.setFormatter(logging.Formatter(precia_log_format))
    loggers.addHandler(file_handler)
    loggers.setLevel(log_level)
    return loggers


logger = setup_logging(logging.INFO)


def create_log_msg(log_msg: str) -> str:
    """
    Aplica el formato adecuado al mensaje log_msg, incluyendo información sobre excepciones.
    """
    error_msg_log_format = "{}. Fallo en linea: {}. Excepcion({}): {}."
    exception_type, exception_value, exception_traceback = exc_info()
    if not exception_type:
        return f"{log_msg}."
    error_line = exception_traceback.tb_lineno
    return error_msg_log_format.format(
        log_msg, error_line, exception_type.__name__, exception_value
    )


def generate_presigned_url(bucket_name, file_key, expirate_time):
    """
    Genera URL firmado para descargar un archivo de un bucket
    """
    signed_url = S3_CLIENT.generate_presigned_url(
        "get_object",
        Params={"Bucket": bucket_name, "Key": file_key},
        ExpiresIn=expirate_time,
    )
    return signed_url.replace(OUTPUT_BUCKET_URL, CLOUDFRONT_URL)


def check_file_exists(bucket_name, file_key):
    """
    Valida si existe un archivo en el bucket
    """
    try:
        S3_CLIENT.head_object(Bucket=bucket_name, Key=file_key)
        return True
    except (Exception,):
        return None


def load_user_from_token(token):
    """
    Obtiene el usuario desde el token
    """
    payload = token.split(".")
    payload_decoded = urlsafe_b64decode(payload[1] + "==")
    payload_decoded = json.loads(payload_decoded)
    user = payload_decoded["unique_name"].split("@")[0]
    return user


def get_api_data_version(version_table_name, valuation_date, now_time):
    """
    Obtiene la version de los datos de la API
    """
    table = DYNAMODB_RESOURCE.Table(version_table_name)
    key = {
        "product": "prices_eod",
        "valuation_date": valuation_date,
    }
    response = table.get_item(Key=key)
    if "Item" in response:
        if response["Item"]["expirate_at"] < now_time:
            return None
        return response["Item"]
    return None


def get_user_valuation_date(clients_params_table_name, user_id):
    """
    Si el cliente parametrizo su consulta retorna para que fecha de valoracion lo hizo
    """
    try:
        params_table = DYNAMODB_RESOURCE.Table(clients_params_table_name)
        params = params_table.get_item(Key={"user_id": user_id})
        if "Item" in params:
            return params["Item"]["valuation_date"]
        return None
    except (Exception,):
        return None


def reponse_with_file(user, valuation_date, api_version, unix_now, add_to_context=""):
    """
    Genera respuesta de la API con url firmada del archivo de datos
    """
    file_path = OUTPUT_FILE_PATH.format(valuation_date=valuation_date, user_id=user)
    if not check_file_exists(OUTPUT_BUCKET_NAME, file_path):
        error_msg = (
            f"No existe el archivo {file_path} en el bucket {OUTPUT_BUCKET_NAME}"
        )
        logger.critical(error_msg)
        raise FileExistsError(error_msg)
    return {
        "statusCode": 200,
        "body": json.dumps(
            {
                "data_url": generate_presigned_url(
                    OUTPUT_BUCKET_NAME, file_path, EXPIRATE_SEC_TIME
                ),
                "version": api_version["version"],
                "stage": api_version["stage"],
                "update_time": api_version["update_time"],
                "query_time": str(unix_now),
                "context": GENERIC_CONTEXT.format(valuation_date=valuation_date)
                + add_to_context,
            },
            cls=DecimalEncoder,
        ),
    }


class DecimalEncoder(json.JSONEncoder):
    """
    Permite transformar numeros de la clase Decimal a string
    """

    def default(self, o):
        if isinstance(o, Decimal):
            return str(o)
        return super().default(o)


def lambda_handler(event, context):
    """
    Función principal de la lambda
    Parameters:
        event (dict): Evento recibido por la lambda.
        context (LambdaContext): Contexto de la lambda.

    Returns:
        dict: Respuesta de la lambda.
    """
    try:
        logger.info("Event:\n%s", json.dumps(event))
        now = dt.now()
        unix_now = int(now.timestamp())
        try:
            valuation_date = event["queryStringParameters"]["valuation-date"]
            dt.strptime(valuation_date, "%Y-%m-%d")
        except (KeyError, TypeError):
            valuation_date = now.strftime("%Y-%m-%d")
        except ValueError:
            logger.error(
                "valuation-date: %s, no tiene formato esperado", valuation_date
            )
            return {
                "statusCode": 400,
                "body": "Formato de 'valuation-date' no valido. Por favor usar YYYY-MM-DD.",
            }
        logger.info("Fecha de consulta: %s", valuation_date)
        api_version = get_api_data_version(VERSION_TABLE_NAME, valuation_date, unix_now)
        if api_version is None:
            logger.info("Aun no hay datos disponibles para la fecha de consulta")
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "data_url": None,
                        "version": 0,
                        "stage": "No Data",
                        "update_time": None,
                        "query_time": str(unix_now),
                        "context": (
                            "No hay datos publicados para Renta Fija Local; "
                            f"Fin de dia {valuation_date}"
                        ),
                    }
                ),
            }
        try:
            if event["queryStringParameters"]["isines"]:
                if event["queryStringParameters"]["isines"].lower() == "all":
                    return reponse_with_file(
                        GENERIC_API_USER, valuation_date, api_version, unix_now
                    )
                return {
                    "statusCode": 400,
                    "body": "para 'isines' solo esta disponible el valor 'all'",
                }
        except (Exception,):
            pass
        user_id = load_user_from_token(event["headers"]["Authentication"])
        logger.info("Usuario: %s", user_id)
        file_path = OUTPUT_FILE_PATH.format(
            valuation_date=valuation_date, user_id=user_id
        )
        if check_file_exists(OUTPUT_BUCKET_NAME, file_path):
            return {
                "statusCode": 200,
                "body": json.dumps(
                    {
                        "data_url": generate_presigned_url(
                            OUTPUT_BUCKET_NAME, file_path, EXPIRATE_SEC_TIME
                        ),
                        "version": api_version["version"],
                        "stage": api_version["stage"],
                        "update_time": api_version["update_time"],
                        "query_time": str(unix_now),
                        "context": GENERIC_CONTEXT.format(
                            valuation_date=valuation_date
                        ),
                    },
                    cls=DecimalEncoder,
                ),
            }
        logger.warning("El archivo %s: %s no existe", OUTPUT_BUCKET_NAME, file_path)
        user_valuation_date = get_user_valuation_date(
            CLIENTS_PARAMS_TABLE_NAME, user_id
        )
        logger.info(
            "Fecha de consulta en la parametrizacion del usuario: %s",
            user_valuation_date,
        )
        if user_valuation_date == valuation_date:
            logger.warning("No se encuentra archivo del usuario que deberia existir")
            if unix_now - int(api_version["update_time"]) > 300:
                logger.error("Supero el timeout de 300s y el archivo no se creo")
                raise TimeoutError(
                    f"El archivo {file_path} deberia existir en el bucket {OUTPUT_BUCKET_NAME}"
                )
            logger.warning("Se hace supuesto que se esta creando")
            return {"statusCode": 201, "body": "Consulta en proceso"}
        if not user_valuation_date:
            add_to_context = "; ALL_ISINES; El usuario no ha parametrizado su consulta en .../config/rfl/prices"
            logger.warning(add_to_context)
        elif user_valuation_date > valuation_date:
            add_to_context = f"; ALL_ISINES; El usuario ha parametrizado su consulta para {user_valuation_date}"
            logger.warning(add_to_context)
        return reponse_with_file(
            GENERIC_API_USER, valuation_date, api_version, unix_now, add_to_context
        )
    except (Exception,):
        error_msg = "No fue posible procesar la solicitud"
        logger.error(create_log_msg(error_msg))
        return {"statusCode": 500, "body": "Error al procesar la solicitud"}
