from datetime import datetime as dt
import json
import logging
import os

import boto3
from boto3.dynamodb.conditions import Attr

logger = logging.getLogger()
logger.setLevel(logging.INFO)


VERSION_TABLE_NAME = os.environ["VERSION_TABLE_NAME"]
DYNAMODB_RESOURCE = boto3.resource("dynamodb")

def update_version_stage(table_name, valuation_date, new_stage, now):
    """
    Actualiza las versiones de la api que tengan determinado valuation_date
    """
    table = DYNAMODB_RESOURCE.Table(table_name)
    response = table.scan(FilterExpression=Attr("valuation_date").eq(valuation_date))
    if not response['Items']:
         logger.warning("No existe una version de datos de la API para el %s", valuation_date)
         return None
    logger.info("versiones disponibles de los datos de la API %s", response['Items'])
    for item in response['Items']:
        try:
            table.update_item(
                Key={
                    'product': item['product'],
                    'valuation_date': item['valuation_date']
                },
                UpdateExpression='SET stage = :val1, update_time = :val2',
                ExpressionAttributeValues={
                    ':val1': new_stage,
                    ':val2': now
                }
            )
            logger.info("product: %s actualizado con stage: %s", item['product'], new_stage)
        except (Exception,):
                logger.error("No se actualizo versiones para %s: %s", item['product'], item['valuation_date'])
                raise
        

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
        now_unix = int(now.timestamp())
        try:
            valuation_date = event["valuation_date"]
            if valuation_date.lower() == "today":
                valuation_date = now.strftime("%Y-%m-%d")
            else:
                dt.strptime(valuation_date, "%Y-%m-%d")
        except KeyError:
            valuation_date = now.strftime("%Y-%m-%d")
        except ValueError:
            error_msg = f"valuation-date: {valuation_date}, no tiene formato esperado"
            logger.error(error_msg)
            raise
        logger.info("Fecha de actualizacion: %s", valuation_date)
        try:
            new_stage = event["new_stage"]
        except KeyError:
            new_stage = "Final"
        logger.info("Nuevo estado de los datos de la API: %s", new_stage)
        update_version_stage(VERSION_TABLE_NAME, valuation_date, new_stage, now_unix)
        logger.info("Actualizacion finalizada")
    except (Exception,):
        logger.error("No fue posible procesar la solicitud")
        raise