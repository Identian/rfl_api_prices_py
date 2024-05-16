"""
Lambda: Obtención de ISINES de clientes en DynamoDB 
Esta lambda se encarga de consultar los ISINES de los clientes en DynamoDB y 
crear un archivo json con los datos.
"""

import decimal
import json
import logging
import os

from boto3 import client as aws_client, resource as aws_resource
from boto3.dynamodb.conditions import Key

logger = logging.getLogger()
logger.setLevel(logging.INFO)

TABLE_PARAMS_NAME = os.environ["TABLE_PARAMS_NAME"]
OUTPUT_BUCKET_NAME = os.environ["OUTPUT_BUCKET_NAME"]
TABLE_ISINES_NAME = os.environ["TABLE_ISINES_NAME"]
OUTPUT_FILE_PATH = os.environ["OUTPUT_FILE_PATH"]


def send_to_s3(response_json, bucket_name, file_path):
    """
    Function to send a JSON string to an S3 bucket with a custom path and name.
    Parameters:
        response_json (str): JSON string to be sent to S3.
        bucket_name (str): Name of the S3 bucket.
        file_path (str): Custom path within the bucket.
    """
    try:
        s3 = aws_client("s3")
        s3.put_object(Body=response_json, Bucket=bucket_name, Key=file_path)
    except (Exception,):
        logger.error("No fue posible generar el archivo %s", file_path)
        raise


def get_records(table_isines_name, table_params_name, user_id):
    """
    Función que se encarga de recuperar los registros en la tabla de DynamoDB isines
    """
    dynamodb = aws_resource("dynamodb")
    logger.info(
        "Consultando datos en la tabla %s para el usuario %s",
        table_params_name,
        user_id,
    )
    params_table = dynamodb.Table(table_params_name)
    params = params_table.query(
        KeyConditionExpression=Key("user_id").eq(user_id), ScanIndexForward=False
    )["Items"][0]
    client_isines = params["isines"]
    keys_list = [client_isines[i : i + 100] for i in range(0, len(client_isines), 100)]
    all_data = []
    logger.info("Consultando los datos de precios en la tabla %s", table_isines_name)
    for keys in keys_list:
        request = {
            table_isines_name: {
                "Keys": [{"isin_code": isin} for isin in keys],
                "ProjectionExpression": ",".join(params["fields"]),
            }
        }
        response = dynamodb.batch_get_item(RequestItems=request)
        all_data += response["Responses"][table_isines_name]
    if len(client_isines) != len(all_data):
        logger.warning(
            "No todos los isines parametizados por el cliente estan disponibles"
        )
        data_isines = set(data["isin_code"] for data in all_data)
        lost_isines = data_isines - set(client_isines)
        logger.info("Completando los isines faltantes con 'error': 'No found'")
        for isin in lost_isines:
            all_data.append({"isin_code": isin, "error": "No Found"})
    return all_data

def delete_sqs_msg(queue_name, receipt_handle):
    """
    Elimina el mensaje de la cola SQS
    """
    sqs_client = aws_client("sqs")
    queue_url = sqs_client.get_queue_url(QueueName=queue_name)["QueueUrl"]
    sqs_client.delete_message(QueueUrl=queue_url,ReceiptHandle=receipt_handle)


class DecimalEncoder(json.JSONEncoder):
    """
    Permite transformar numeros de la clase Decimal a string
    """

    def default(self, o):
        if isinstance(o, decimal.Decimal):
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
        body = json.loads(event["Records"][0]["body"])
        receipt_handle = event["Records"][0]['receiptHandle']
        queue_name = event["Records"][0]['eventSourceARN'].split(":")[-1]
        delete_sqs_msg(queue_name, receipt_handle)
        user_id = body["user_id"].split("@")[0]
        current_date = body["valuation_date"]
        logger.info("user_id: %s; fecha: %s", user_id, current_date)
        file_path = OUTPUT_FILE_PATH.format(
            valuation_date=current_date, user_id=user_id
        )
        file_data = json.dumps(
            {"data": get_records(TABLE_ISINES_NAME, TABLE_PARAMS_NAME, user_id)},
            indent=4,
            cls=DecimalEncoder,
        )
        logger.info("Generando archivo ...")
        send_to_s3(file_data, OUTPUT_BUCKET_NAME, file_path)
        logger.info("bucket: %s, file_path: %s", OUTPUT_BUCKET_NAME, file_path)
        return "Archivo disponible"
    except (Exception,) as error:
        logger.error(
            "Se interrumpio la generación del archivo con la data personalizada: %s",
            error,
        )
        raise
