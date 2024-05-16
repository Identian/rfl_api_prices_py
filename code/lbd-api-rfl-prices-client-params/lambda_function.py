"""
Lambda: Insersión datos de ISINES de clientes en DynamoDB 
Esta lambda se encarga de hacer la inserción de los ISINES de los clientes en DynamoDB
"""

import json
import logging
import os
from sys import exc_info, stdout
import boto3

from base64 import urlsafe_b64decode
from datetime import datetime, timedelta


VALID_FIELDS = [
    "isin_code",
    "instrument",
    "issue_num",
    "valuation_date",
    "issue_date",
    "maturity_date",
    "payment_frequency",
    "maturity_days",
    "currency_type",
    "rate_type",
    "spread",
    "calculation_type",
    "mean_price",
    "clean_price",
    "margin_value",
    "yield",
    "equivalent_margin",
    "duration",
    "modified_duration",
    "convexity",
    "accrued_interest",
    "real_rating",
]

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

def create_records(table_name, payload):
    """
    Función que se encarga de crear los registros en la tabla de DynamoDB
    Parameters:
        table_name (str): Nombre de la tabla de DynamoDB.
        payload (dict): Payload con los datos a insertar en la tabla.
    """
    dynamodb = boto3.resource("dynamodb")
    table = dynamodb.Table(table_name)
    logger.info("Insertando datos en la tabla: %s ...", table_name)
    table.put_item(Item=payload)


def load_user_from_token(token):
    """
    Obtiene el correo del usuario desde el token
    """
    user = ""
    payload = token.split(".")
    if len(payload) > 1:
        payload_decoded = urlsafe_b64decode(payload[1] + "==")
        payload_decoded = json.loads(payload_decoded)
        user = payload_decoded["unique_name"]
    else:
        logger.info(
            "No ha llegado un JWT con la estructura esperada. No se devuelve usuario."
        )
    return user


def validate_fields(fields):
    """
    Valida que los campos parametrizados por el cliente esten disponibles para consultar
    """
    error_fields = []
    for field in fields:
        if field not in VALID_FIELDS:
            error_fields.append(field)
    return ", ".join(error_fields)


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
        request_time = datetime.now() - timedelta(hours=5)
        logger.info("Event:\n%s", json.dumps(event))
        jwt_token = event["headers"]["Authentication"]
        user_id = load_user_from_token(jwt_token).split("@")[0]
        logger.info("Actualizando parametrizacion para el usuario: %s ...", user_id)
        fields = list(set(json.loads(event["body"])["fields"]))
        error_fields = validate_fields(fields)
        if error_fields:
            error_msg = f"ERROR: Los siguientes campos no son validos: {error_fields}"
            logger.error(error_msg)
            return {
                "statusCode": 400,
                "body": error_msg,
            }
        if "isin_code" not in fields:
            fields.append("isin_code")
        isines = list(set(json.loads(event["body"])["isines"]))
        if not isines:
            error_msg = "ERROR: Lista de isines vacia"
            logger.error(error_msg)
            return {"statusCode": 400, "body": error_msg}
        if request_time.strftime("%H:%M") > os.environ["MAX_CONFIG_CO_TIME"]:
            valuation_date = (request_time + timedelta(hours=24)).strftime("%Y-%m-%d")
        else:
            valuation_date = request_time.strftime("%Y-%m-%d")
        payload = {
            "user_id": user_id,
            "isines": isines,
            "fields": fields,
            "created_at": request_time.strftime("%Y-%m-%d %H:%M:%S.%f"),
            "valuation_date": valuation_date,
        }
        create_records(os.environ["TABLE_NAME"], payload)
        success_msg = (
            "Se configuro exitosamente. Podra consultar los datos para la "
            f"la fecha de valoracion {valuation_date}"
        )
        logger.info(success_msg)
        return {
            "statusCode": 200,
            "body": success_msg,
        }
    except (Exception,):
        error_msg = "Error inesperado al ejecutar la solicitud"
        logger.error(create_log_msg(error_msg))
        return {
            "statusCode": 500,
            "body": error_msg,
        }
