"""
Glue, Python 3.9
- Carga todos los precios de isines disponibles en Dynamodb
- Envia a una cola SQS los usuarios que han parametrizado su consulta para la generacion
  de archivos .json personalizados, que seran consultados por medio de la API.
- Genera un archivo .json con todos los isines para que sea consultado por los clientes
  no han parametrizado su consulta.
- Actualiza la version de datos de la API que permite la consulta de los archivos .json
"""
from base64 import b64decode
import decimal
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from json import loads as json_loads, dumps as json_dumps, JSONEncoder
import logging
import smtplib
from sys import argv, exc_info, stdout
from time import time
from datetime import datetime, timedelta

from awsglue.utils import getResolvedOptions
from boto3 import client as aws_client, resource as aws_resource
from boto3.dynamodb.conditions import Key, Attr
import pymysql

# -------------------------------------------------------------------------------------------------
# AWS Services
DYNAMODB_RESOURCE = aws_resource("dynamodb")
DYNAMODB_PRICES_TABLE = "dnb-api-rfl-prices-all-isines"
DYNAMODB_CLIENT_PARAMS_TABLE = "dnb-api-rfl-prices-client-params"
DYNAMODB_API_VERSION_TABLE = "dnb-api-rfl-version"


# -------------------------------------------------------------------------------------------------
# PRECIA_UTILS_EXCEPTIONS
class BaseError(Exception):
    """Exception personalizada para la capa precia_utils"""


# -------------------------------------------------------------------------------------------------
class PlataformError(BaseError):
    """
    Clase heredada de BaseError que permite etiquetar las excepciones causadas por
    errores del sistema identificados
    """

    def __init__(
        self,
        error_message="La plataforma presenta un error, ver el log para mas detalles",
    ):
        self.error_message = error_message
        super().__init__(self.error_message)

    def __str__(self):
        return str(self.error_message)


# -------------------------------------------------------------------------------------------------
# CONFIGURACIÓN DEL SISTEMA DE LOGS
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


LOG = setup_logging(logging.INFO)


# -------------------------------------------------------------------------------------------------
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


# -------------------------------------------------------------------------------------------------
def get_params(parameter_list) -> dict:
    """Obtiene los parametros de entrada del glue
    Parameters:
        parameter_list (list): Lista de parametros

    Returns:
        dict: Valor de los parametros
    """
    try:
        LOG.info("Obteniendo parametros del glue job ...")
        params = getResolvedOptions(argv, parameter_list)
        LOG.info("Todos los parametros fueron encontrados")
        return params
    except Exception as sec_exc:
        error_msg = (
            f"No se encontraron todos los parametros solicitados: {parameter_list}"
        )
        LOG.error(create_log_msg(error_msg))
        raise PlataformError(error_msg) from sec_exc


# -------------------------------------------------------------------------------------------------
def get_secret(secret_name: str) -> dict:
    """
    Obtiene secretos almacenados en el servicio Secrets Manager de AWS.
    Parameters:
        secret_name (str): Nombre del secreto en el servicio AWS.

    Returns:
        dict: Secreto con la informacion desplegada en Secrets Manager AWS.
    """
    try:
        LOG.info('Intentando obtener secreto: "%s" ...', secret_name)
        secret_client = aws_client("secretsmanager")
        secret_data = secret_client.get_secret_value(SecretId=secret_name)
        if "SecretString" in secret_data:
            secret_str = secret_data["SecretString"]
        else:
            secret_str = b64decode(secret_data["SecretBinary"])
        LOG.info("Se obtuvo el secreto.")
        return json_loads(secret_str)
    except (Exception,) as sec_exc:
        error_msg = f'Fallo al obtener el secreto "{secret_name}"'
        LOG.error(create_log_msg(error_msg))
        raise PlataformError(error_msg) from sec_exc


# -------------------------------------------------------------------------------------------------
class SqsQueue:
    """
    Abstrae una Cola SQS de AWS
    """

    def __init__(self, name: str) -> None:
        """
        Abstrae la implementacion de una cola SQS
        """
        try:
            self.client = aws_client("sqs")
            self.url = self.client.get_queue_url(QueueName=name)["QueueUrl"]
            self.name = name
        except (Exception,) as sqs_exc:
            error_msg = f"No fue posible configurar la cola SQS: {name}"
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from sqs_exc

    def send_msg(self, message, id_msg) -> None:
        """
        Envia mensajes a la cola SQS
        """
        try:
            response = self.client.send_message(
                QueueUrl=self.url,
                MessageBody=json_dumps(message),
                MessageGroupId=id_msg,
            )
            return response["MessageId"]
        except (Exception,) as sqs_exc:
            error_msg = (
                f"Error al enviar mensaje a la SQS: {self.name}, mensaje: {message}"
            )
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from sqs_exc


# -------------------------------------------------------------------------------------------------
class DynamodbTable:
    """
    Abstrae una tabla DynamoDB de AWS
    """

    def __init__(self, name: str) -> None:
        """
        Gestiona la conexion y las transacciones de una tabla dynamoDB
        """
        try:
            self.table = DYNAMODB_RESOURCE.Table(name)
        except (Exception,) as dyn_exc:
            error_msg = f"No fue posible conectarse a la tabla DynamoDB: {name}"
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from dyn_exc

    def write_batch(self, items: list, date: str, data_expiration_time: str) -> list:
        """
        Pone paquetes de items en la tabla DynamoDB
        """
        try:
            LOG.info("Escribiendo items en la tabla DynamoDB: %s ... ",
                     self.table.name)
            LOG.debug("Primer item: %s", items[0])
            LOG.debug("Ultimo item: %s", items[-1])
            all_items = []
            with self.table.batch_writer() as writer:
                for item in items:
                    item["valuation_date"] = date
                    all_items.append(item.copy())
                    item["expirate_at"] = data_expiration_time
                    writer.put_item(Item=item)
            LOG.info("tabla DynamoDB: %s actualizada con exito", self.table.name)
            return all_items
        except (Exception,) as dyn_exc:
            error_msg = (
                "No fue posible escribir todos los items en la tabla "
                f"DynamoDB: {self.table.name}"
            )
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from dyn_exc

    def scan(self, **kwargs) -> list:
        """Obtiene los items de la tabla DynamoDB gestionando paginacion"""
        try:
            LOG.info(
                "Obteniendo todos los items de la tabla DynamoDB: %s ... ",
                self.table.name,
            )
            response = self.table.scan(**kwargs)
            data = response["Items"]
            while "LastEvaluatedKey" in response:
                response = self.table.scan(
                    ExclusiveStartKey=response["LastEvaluatedKey"], **kwargs
                )
                data.extend(response["Items"])
            LOG.info("tabla DynamoDB: %s consultada con exito", self.table.name)
            return data
        except (Exception,) as dyn_exc:
            error_msg = (
                "No fue posible scanear todos los items de la tabla "
                f"DynamoDB: {self.table.name}"
            )
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from dyn_exc


# -------------------------------------------------------------------------------------------------
class MysqlDB:
    """
    Abstrae una base de datos MySQL
    """

    def __init__(self, secret: dict) -> None:
        """
        Gestiona la conexion y las transacciones a base de datos
        """
        try:
            self.host = secret["host"]
            self.port = int(secret["port"])
            self.username = secret["username"]
            self.password = secret["password"]
        except (Exception,) as db_exc:
            error_msg = "El secreto de la base de datos no tiene las llaves esperadas"
            LOG.error(create_log_msg(error_msg))
            raise PlataformError(error_msg) from db_exc

    def execute_select_query(self, query: str, params: dict) -> list:
        """
        Ejecuta query select
        """
        try:
            LOG.info("Conectandose a la base de datos ...")
            with pymysql.connect(
                host=self.host,
                port=self.port,
                user=self.username,
                password=self.password,
                cursorclass=pymysql.cursors.DictCursor,
            ) as connection:
                LOG.info("Conexion exitosa")
                LOG.info("Ejecutando query SELECT en base de datos ...")
                LOG.debug("query: %s", query)
                with connection.cursor() as cursor_connection:
                    cursor_connection.execute(query, params)
                    LOG.info(
                        "Query SELECT exitoso. Filas: %s", cursor_connection.rowcount
                    )
                    if cursor_connection.rowcount <= 0:
                        raise PlataformError(
                            "No se encontraron datos en la base de datos"
                        )
                    results = cursor_connection.fetchall()
                    LOG.debug("Primera fila obtenida: %s", results[0])
                    LOG.debug("Ultima fila obtenida: %s", results[-1])
            return results
        except (Exception,) as conn_exc:
            raise_msg = f"No fue posible ejecutar el query: {query}"
            LOG.error(create_log_msg(raise_msg))
            raise PlataformError(raise_msg) from conn_exc

    def get_prices(self, date: str):
        """
        Consulta los precios RFL para valuation_date
        """
        table_columns = (
            "isin_code, instrument, issue_num, CAST(issue_date as CHAR) AS issue_date, "
            "CAST(maturity_date as CHAR) AS maturity_date, payment_frequency, maturity_days, "
            "currency_type, rate_type, spread, calculation_type, mean_price, clean_price, "
            "margin_value, yield, equivalent_margin, duration, modified_duration, convexity, "
            "accrued_interest, real_rating"
        )
        clause_where = "valuation_date = %(valuation_date)s AND isin_code != ''"
        query = f"SELECT {table_columns} FROM precia_published.pub_rfl_prices WHERE {clause_where}"
        params = {"valuation_date": date}
        try:
            LOG.info(
                "Obteniendo RFL precios EoD para %s desde la base de datos ...", date
            )
            prices = self.execute_select_query(query, params)
            LOG.info("RFL precios EoD obtenidos exitosamente")
            return prices
        except (Exception,) as conn_exc:
            raise_msg = "No fue posible Obtener RFL precios EoD de la base de datos"
            LOG.error(create_log_msg(raise_msg))
            raise PlataformError(raise_msg) from conn_exc


# -------------------------------------------------------------------------------------------------
def load_price_data(
    mysql_secret_id: str,
    valuation_date: str,
    prices_table_name: str,
    data_expiration_time: int,
):
    """
    Consulta los datos RFL precios fin de dia en una base de datos MySQL para cargarlos en la
    tabla DynamoDB "prices_table_name" para su consulta
    """
    try:
        LOG.info("Cargando datos de RFL precios EoD a DynamoDB ...")
        pub_db = MysqlDB(get_secret(mysql_secret_id))
        prices_eod = pub_db.get_prices(valuation_date)
        prices_eod_table = DynamodbTable(prices_table_name)
        all_data = prices_eod_table.write_batch(
            prices_eod, valuation_date, data_expiration_time
        )
        LOG.info("Datos RFL precios EoD cargados exitosamente en DynamoDB")
        LOG.info("Identificando datos obsoletos ...")
        items_to_delete = prices_eod_table.scan(
            FilterExpression=Attr('expirate_at').lt(data_expiration_time),
            ProjectionExpression="isin_code")
        if items_to_delete:
            LOG.info("Eliminando Precios no actualizados ...")
            for item in items_to_delete:
                prices_eod_table.table.delete_item(
                    Key={
                        'isin_code': item['isin_code'],
                    }
                )
            LOG.info("Todos los items no actualizados fueron eliminados")
        else:
            LOG.info("No hay datos obsoletos")
        return all_data
    except (Exception,):
        LOG.error(
            create_log_msg(
                "Se interrumpio el proceso de carga de RFL precios a DynamoDB"
            )
        )
        raise


# -------------------------------------------------------------------------------------------------
def gen_file_price_per_client(
    params_table_name: str, gen_file_sqs_name: str, data_date: str
) -> None:
    """
    Consulta la parametrizacion de los clientes para generar archivos personalizados de RFL precios
    EoD para enviar mensajes por una cola SQS para invocar su creacion en S3
    """
    try:
        LOG.info(
            "Invocando generacion de archivos personalizados RFL precios EoD por Cliente ..."
        )
        client_params_table = DynamodbTable(params_table_name)
        clients = client_params_table.scan(
            ProjectionExpression="user_id,valuation_date"
        )
        gen_file_sqs = SqsQueue(gen_file_sqs_name)
        now_time = str(time())
        today_date = (datetime.today() + timedelta(hours=5)
                      ).strftime("%Y-%m-%d")
        for client in clients:
            if client["valuation_date"] <= today_date:
                user_id = client["user_id"]
                message = {"user_id": user_id, "valuation_date": data_date}
                msg_id = gen_file_sqs.send_msg(
                    message, f"{user_id}_{now_time}")
                LOG.info(
                    "Invocada la generacion para el cliente: %s; msg_id: %s",
                    user_id,
                    msg_id
                )
        LOG.info(
            "Todos los archivos personalizados se estan generando en este momento")
    except (Exception,):
        LOG.error(
            create_log_msg(
                "Se interrumpio la generacion de archivos personalizados por cliente"
            )
        )
        raise


# -------------------------------------------------------------------------------------------------
def get_data_expiration_time(valuation_date, data_expiration_co_time):
    """
    Determina el timestamp en formato epoca unix para la expiracion de datos para dynamodb en UTC
    """
    try:
        LOG.info(
            "Determinando la fecha de expiracion de los items en tablas DyanmoDB ...")
        data_date = datetime.strptime(valuation_date, "%Y-%m-%d")
        today_date = datetime.today()
        if data_date >= today_date + timedelta(hours=5):
            expiration_co_time_str = f"{valuation_date} {data_expiration_co_time}:00"
            expiration_utc_time = (
                datetime.strptime(expiration_co_time_str, "%Y-%m-%d %H:%M:%S")
                - timedelta(hours=5)
                + timedelta(days=1)
            )
            expiration_utc_time_int = int(expiration_utc_time.timestamp())
        else:
            # SOLO PARA PRUEBAS: 4 horas
            expiration_utc_time_int = int(time()) + 4 * 60 * 60
        LOG.info("Fecha de valoracion: %s", valuation_date)
        LOG.info("timestamp de expiracion: %s", expiration_utc_time_int)
        return expiration_utc_time_int
    except (Exception,):
        LOG.error(
            create_log_msg(
                "Error al determinar el timestamp de expiracion de datos para DynamoDB"
            )
        )
        raise


# -------------------------------------------------------------------------------------------------
def upload_generic_price_file(all_data, bucket_name, file_path):
    """
    Funcion que carga en bucket_name el archivo file_path con todos los isenes para clientes no
    han parametrizado
    """
    try:
        LOG.info("Cargando archivo generico para clientes no parametrizados ...")
        file_data = json_dumps(
            {"data": all_data}, indent=4, cls=DecimalEncoder)
        s3 = aws_client("s3")
        s3.put_object(Body=file_data, Bucket=bucket_name, Key=file_path)
        LOG.info("Archivo disponible. Bucket: %s; Path: %s",
                 bucket_name, file_path)
    except (Exception,):
        LOG.error(
            create_log_msg(
                "No fue posible cargar el archivo con todos los isines para clientes no registrados"
            )
        )
        raise


# -------------------------------------------------------------------------------------------------
def update_api_data_version(
    verion_table_name: str, valuation_date: str, data_expiration_time: str
):
    """
    Actualiza la version de la data de la API
    """
    try:
        LOG.info("Actualizando la version de la API ...")
        new_version = {
            "product": "prices_eod",
            "valuation_date": valuation_date,
            "stage": "preliminary",
            "update_time": int(time()),
            "expirate_at": data_expiration_time,
        }
        data_version_table = DynamodbTable(verion_table_name)
        key = {
            "product": "prices_eod",
            "valuation_date": valuation_date,
        }
        version = data_version_table.table.get_item(Key=key)
        if "Item" not in version:
            LOG.info("Actual version: %s", "No Data")
            new_version["version"] = 1
        else:
            current_version = version["Item"]
            LOG.info("Actual version: %s", current_version)
            new_version["version"] = current_version["version"] + 1
        data_version_table.table.put_item(Item=new_version)
        LOG.info("Nueva version Actualizada: %s", new_version)
    except (Exception,):
        LOG.error(
            create_log_msg(
                "Se interrumpio al actualizar la version de los datos de la API"
            )
        )
        raise


# -------------------------------------------------------------------------------------------------
def send_email(email_connection, subject, message, job_name):
    """
    Funcionalidad de envio de correos en caso de alerta.
    """
    try:
        message = (
            "Coordial saludo,\n \nDurante el proceso de información de API-RFL-prices en AWS "
            f"se presento una novedad. El origen de la alerta es el glue '{job_name}', "
            "por favor revisar el log de la ultima de la ejecución desde la consola para más "
            f"detalles.\n\nMensaje informado: {message}\n\n\nAlertas automatizadas para API Precia."
        )

        msg = MIMEMultipart()
        msg["From"] = email_connection["email_from"]
        msg["To"] = email_connection["email_to"]
        msg["Subject"] = subject

        # Add body to email
        msg.attach(MIMEText(message, "plain"))

        # Create SMTP session
        with smtplib.SMTP(
            email_connection["server"], email_connection["port"]
        ) as server:
            server.starttls()
            server.login(email_connection["user"],
                         email_connection["password"])
            server.send_message(msg)
    except Exception as e:
        LOG.error(
            create_log_msg(
                f"Ocurrio un error al enviar correo a usuario final: {str(e)}"
            )
        )
        raise PlataformError(
            "No fue posible enviar correo a usuario final") from e


# -------------------------------------------------------------------------------------------------
class DecimalEncoder(JSONEncoder):
    """
    Permite transformar numeros de la clase Decimal a string
    """

    def default(self, o):
        if isinstance(o, decimal.Decimal):
            return str(o)
        return super().default(o)


# -------------------------------------------------------------------------------------------------
def main():
    """
    Metdodo principal de la funcionalidad
    """
    parameters = [
        "VALUATION_DATE",
        "DB_SECRET",
        "EMAIL_SECRET",
        "JOB_NAME",
        "GEN_FILES_SQS",
        "DATA_EXPIRATION_CO_TIME",
        "OUTPUT_BUCKET_NAME",
        "OUTPUT_GENERIC_FILE_PATH",
    ]
    params_glue = get_params(parameters)
    email_secret_id = params_glue["EMAIL_SECRET"]
    job_name = params_glue["JOB_NAME"]
    valuation_date = params_glue["VALUATION_DATE"]
    email_secret = get_secret(email_secret_id)
    try:
        LOG.info("Inicia el proceso de la ETL API RFL precios EoD ...")
        data_expiration_time = get_data_expiration_time(
            valuation_date, params_glue["DATA_EXPIRATION_CO_TIME"]
        )
        all_price_data = load_price_data(
            params_glue["DB_SECRET"],
            valuation_date,
            DYNAMODB_PRICES_TABLE,
            data_expiration_time,
        )
        gen_file_price_per_client(
            DYNAMODB_CLIENT_PARAMS_TABLE, params_glue["GEN_FILES_SQS"], valuation_date
        )
        generic_price_file_path = params_glue["OUTPUT_GENERIC_FILE_PATH"].format(
            valuation_date=valuation_date
        )
        upload_generic_price_file(
            all_price_data, params_glue["OUTPUT_BUCKET_NAME"], generic_price_file_path
        )
        update_api_data_version(
            DYNAMODB_API_VERSION_TABLE, valuation_date, data_expiration_time
        )
        LOG.info("Finaliza el proceso de la ETL API RFL precios EoD")
    except (Exception,) as error:
        error_message = f"Se presento el siguiente error en la ejecución: {error}"
        error_subject = (
            f"API RFL EoD: Error al generar los archivos personalizados: {valuation_date}")
        LOG.error(create_log_msg(error_message))
        send_email(email_secret, error_subject, error_message, job_name)
        raise PlataformError(error_message) from error


# -------------------------------------------------------------------------------------------------
if __name__ == "__main__":
    main()
