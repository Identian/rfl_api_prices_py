import os
import json
import boto3
import logging
import ast

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event, context):
    try:
        client = boto3.client("glue")
        glue_job_name = os.environ["JOB_NAME"]
        message = event["Records"][0]["Sns"]["Message"]
        print(f"El mensaje de SNS es: {message}")
        message_dictionary = ast.literal_eval(message)
        response = client.start_job_run(
            JobName=glue_job_name,
            Arguments={
                "--VALUATION_DATE": message_dictionary["VALUATION_DATE"],
                "--JOB_NAME": glue_job_name,
            },
        )
        job_run_id = response["JobRunId"]
        logger.info("Se lanz el Glue - API RFL Prices EoD: %s.", job_run_id)
        return {
            "statusCode": 200,
            "body": json.dumps("Se lanzaron el/los Glue correctamente"),
        }
    except Exception:
        logger.error("Error iniciando el Glue para API RFL Prices EoD")
        raise
