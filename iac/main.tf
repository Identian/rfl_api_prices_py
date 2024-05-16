##########################################################################################
# IAC - API PRECIOS
# Descripcion:
# Este módulo corresponde a la creación de los componentes de la API de precios
##########################################################################################
# Identidad de la cuenta
data "aws_caller_identity" "AccountID" {}
#-----------------------------------------------------------------------------------------
# Zip Files
data "archive_file" "file_lbd_client_isines" {
  type = "zip"
  source_file = "../code/lbd-api-rfl-prices-client-isines/lambda_function.py"
  output_path = "lbd-api-rfl-prices-client-isines.zip"
}

data "archive_file" "file_lbd_client_params" {
  type = "zip"
  source_file = "../code/lbd-api-rfl-prices-client-params/lambda_function.py"
  output_path = "lbd-api-rfl-prices-client-params.zip"
}

data "archive_file" "file_lbd_file_gen" {
  type = "zip"
  source_file = "../code/lbd-api-rfl-prices-file-gen/lambda_function.py"
  output_path = "lbd-api-rfl-prices-file-gen.zip"
}

data "archive_file" "file_lbd_token_checking" {
  type = "zip"
  source_dir = "../code/lbd-api-rfl-token-checking"
  output_path = "lbd-api-rfl-token-checking.zip"
}

data "archive_file" "file_lbd_etl_prices_eod" {
  type = "zip"
  source_dir = "../code/lbd-api-rfl-trigger-elt-prices-eod"
  output_path = "lbd-api-rfl-trigger-elt-prices-eod.zip"
}

data "archive_file" "file_lbd_update_final_version" {
  type = "zip"
  source_dir = "../code/lbd-api-rfl-update-final-version"
  output_path = "lbd-api-rfl-update-final-version.zip"
}

#------------------------------------------------------------------
# DATASOURCE DE COMPONENTES DESPLEGADOS
data "aws_sns_topic" "sns_trigger_all_eod" {
  name = format("sns-%s-rfli-trigger-all-eod", var.environment)
}

data "aws_wafv2_web_acl" "waf" {
  name  = var.waf_name
  scope = "CLOUDFRONT"
}

#-----------------------------------------------------------------------------------------
# INICIA LA CREACIÓN DE SECRETOS
# Secreto de correo
resource "aws_secretsmanager_secret" "sm_mail" {
  name = format("sm-%s-api-rfl-mail", var.environment)
  description = "Secreto con las credenciales de mail"
  recovery_window_in_days = 0
}

# Asignación valor del secreto de correo
resource "aws_secretsmanager_secret_version" "secret_value_mail" {
  secret_id = aws_secretsmanager_secret.sm_mail.id
  secret_string = jsonencode(var.secret_mail_map)
}

# Secreto de db
resource "aws_secretsmanager_secret" "sm_db" {
  name = format("sm-%s-api-rfl-prices-db", var.environment)
  description = "Secreto con las credenciales de base de datos"
  recovery_window_in_days = 0
}

# Asignación valor del secreto de db
resource "aws_secretsmanager_secret_version" "secret_value_db" {
  secret_id = aws_secretsmanager_secret.sm_db.id
  secret_string = jsonencode(var.secret_db_map)
}

# Secreto de b2c
resource "aws_secretsmanager_secret" "sm_b2c" {
  name = format("sm-%s-api-b2c-client", var.environment)
  description = "Secreto de b2c"
  recovery_window_in_days = 0
}

# Asignación valor del secreto de b2c
resource "aws_secretsmanager_secret_version" "secret_value_b2c" {
  secret_id = aws_secretsmanager_secret.sm_b2c.id
  secret_string = jsonencode(var.secret_b2c_map)
}

#------------------------------------------------------------------
# S3 DEL CÓDIGO FUENTE DE LA SOLUCIÓN

resource "aws_s3_bucket" "s3_api_prices_code" {
  bucket = format("s3-%s-rfl-api-prices-code", var.environment)
}

# recurso de bloqueo del s3 del codigo fuente
resource "aws_s3_bucket_public_access_block" "bpab_s3_rfl_api_prices_code" {
  bucket = aws_s3_bucket.s3_api_prices_code.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA PRICES CLIENT PARAM
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_prices_client_params" {
  name = format("rol-%s-lbd-layer-api-prices-client-params", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_rfl_prices_client_params" {
  name = "policy-irp-lbd-layer-rfl-prices-client-params"
  role = aws_iam_role.rol_lbd_api_prices_client_params.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "dynamodb:PutItem"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_dynamodb_table.table_client_params.arn}"
          ]
        }
    ]
  })
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_prices_client_params" {
  filename      = data.archive_file.file_lbd_client_params.output_path
  source_code_hash = data.archive_file.file_lbd_client_params.output_base64sha256
  function_name = format("lbd-%s-layer-api-rfl-prices-client-params", var.environment)
  role          = aws_iam_role.rol_lbd_api_prices_client_params.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 5

  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }
  environment {
    variables = {
      TABLE_NAME = aws_dynamodb_table.table_client_params.name
      MAX_CONFIG_CO_TIME = "15:00"
    }
  }

  depends_on = [ aws_iam_role_policy.irp_lbd_rfl_prices_client_params ]
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA PRICES CLIENT ISINES
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_prices_client_isines" {
  name = format("rol-%s-lbd-layer-api-prices-client-isines", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_rfl_prices_client_isines" {
  name = "policy-irp-lbd-layer-rfl-prices-client-isines"
  role = aws_iam_role.rol_lbd_api_prices_client_isines.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "s3:GetObject",
            "s3:ListBucket"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_s3_bucket.s3_api_rfl_output.arn}",
            "${aws_s3_bucket.s3_api_rfl_output.arn}/*"
          ]
        },
        {
          Action = [
            "dynamodb:GetItem"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_dynamodb_table.table_version.arn}",
            "${aws_dynamodb_table.table_client_params.arn}"
          ]
        }
    ]
  })
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_prices_client_isines" {
  filename      = data.archive_file.file_lbd_client_isines.output_path
  source_code_hash = data.archive_file.file_lbd_client_isines.output_base64sha256
  function_name = format("lbd-%s-layer-api-rfl-prices-client-isines", var.environment)
  role          = aws_iam_role.rol_lbd_api_prices_client_isines.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 5
  
  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }

  depends_on = [ 
    aws_iam_role_policy.irp_lbd_rfl_prices_client_isines,
  ]
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA PRICES FILE GEN
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_prices_file_gen" {
  name = format("rol-%s-lbd-layer-api-rfl-prices-file-gen", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_api_prices_file_gen" {
  name = "policy-irp-lbd-layer-api-rfl-prices-file-gen"
  role = aws_iam_role.rol_lbd_api_prices_file_gen.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "s3:PutObject"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_s3_bucket.s3_api_rfl_output.arn}",
            "${aws_s3_bucket.s3_api_rfl_output.arn}/*"
          ]
        },
        {
          Action = [
            "dynamodb:Query",
            "dynamodb:BatchGetItem",
          ]
          Effect = "Allow"
          Resource = [
            "${aws_dynamodb_table.table_all_isines.arn}",
            "${aws_dynamodb_table.table_client_params.arn}"
          ]
        },
        {
          Action = [
            "sqs:GetQueueUrl",
            "sqs:ReceiveMessage",
            "sqs:DeleteMessage",
            "sqs:GetQueueAttributes"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_sqs_queue.sqs_fifo_file_gen.arn}"
          ]
        }
    ]
  })
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_prices_file_gen" {
  filename      = data.archive_file.file_lbd_file_gen.output_path
  source_code_hash = data.archive_file.file_lbd_file_gen.output_base64sha256
  function_name = format("lbd-%s-api-rfl-prices-file-gen", var.environment)
  role          = aws_iam_role.rol_lbd_api_prices_file_gen.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 600
  
  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }

  environment {
    variables = {
      OUTPUT_BUCKET_NAME	= aws_s3_bucket.s3_api_rfl_output.bucket
      TABLE_ISINES_NAME	= aws_dynamodb_table.table_all_isines.name
      TABLE_PARAMS_NAME = aws_dynamodb_table.table_client_params.name
      OUTPUT_FILE_PATH = "prices/{valuation_date}/api_rfl_prices_{user_id}_{valuation_date}.json"
    }
  }

  depends_on = [ aws_iam_role_policy.irp_lbd_api_prices_file_gen ]
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA UPDATE FINAL VERSION
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_update_final_version" {
  name = format("rol-%s-lbd-api-rfl-update-final-version", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_api_update_final_version" {
  name = "policy-irp-lbd-api-rfl-update-final-version"
  role = aws_iam_role.rol_lbd_api_update_final_version.id 
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "dynamodb:UpdateItem",
            "dynamodb:Scan"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_dynamodb_table.table_version.arn}"
          ]
        }
    ]
  })
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_update_final_version" {
  filename      = data.archive_file.file_lbd_update_final_version.output_path
  source_code_hash = data.archive_file.file_lbd_update_final_version.output_base64sha256
  function_name = format("lbd-%s-api-rfl-update-final-version", var.environment)
  role          = aws_iam_role.rol_lbd_api_update_final_version.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 5
  
  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }

  environment {
    variables = {
      VERSION_TABLE_NAME = aws_dynamodb_table.table_version.name
    }
  }

  depends_on = [ aws_iam_role_policy.irp_lbd_api_update_final_version ]
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA ETL PRICES EOD
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_etl_prices_eod" {
  name = format("rol-%s-lbd-trigger-api-rfl-etl-prices-eod", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_api_etl_prices_eod" {
  name = "policy-irp-lbd-trigger-api-rfl-etl-prices-eod"
  role = aws_iam_role.rol_lbd_api_etl_prices_eod.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "glue:StartJobRun"
          ]
          Effect = "Allow"
          Resource = "${aws_glue_job.glue_api_etl_prices_eod.arn}"
        }
    ]
  })
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_etl_prices_eod" {
  filename      = data.archive_file.file_lbd_etl_prices_eod.output_path
  source_code_hash = data.archive_file.file_lbd_etl_prices_eod.output_base64sha256
  function_name = format("lbd-%s-trigger-api-rfl-etl-prices-eod", var.environment)
  role          = aws_iam_role.rol_lbd_api_etl_prices_eod.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 5
  
  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }
  environment {
    variables = {
      JOB_NAME = aws_glue_job.glue_api_etl_prices_eod.name
    }
  }

  depends_on = [ aws_iam_role_policy.irp_lbd_api_etl_prices_eod ]
}

# Permission SNS
resource "aws_lambda_permission" "trigger_all_intra" {
  statement_id  = "AllowExecutionFromSNS"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lbd_api_rfl_etl_prices_eod.function_name
  principal     = "sns.amazonaws.com"
  source_arn    = data.aws_sns_topic.sns_trigger_all_eod.arn
}

# Suscription SNS
resource "aws_sns_topic_subscription" "trigger_all_intra_suscription" {
  topic_arn = data.aws_sns_topic.sns_trigger_all_eod.arn
  protocol  = "lambda"
  endpoint  = aws_lambda_function.lbd_api_rfl_etl_prices_eod.arn
  depends_on = [ aws_lambda_permission.trigger_all_intra ]
}

#-----------------------------------------------------------------
# INICIA LA CREACIÓN DE LA LAMBDA TOKEN CHECKING
# Rol de la Lambda
resource "aws_iam_role" "rol_lbd_api_token_checking" {
  name = format("rol-%s-lbd-layer-api-rfl-token-checking", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "lambda.amazonaws.com"
            } 
        },
    ]
  })
}

# Política de la lambda
resource "aws_iam_role_policy" "irp_lbd_api_checking_token" {
  name = "policy-irp-lbd-layer-api-rfl-checking-token"
  role = aws_iam_role.rol_lbd_api_token_checking.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:CreateTags",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = [
              "*"
            ]
        },
        {
          Action = [
            "kms:Decrypt",
            "secretsmanager:GetSecretValue"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_secretsmanager_secret.sm_b2c.arn}",
            format("arn:aws:kms:us-east-1:%s:key/%s", data.aws_caller_identity.AccountID.account_id, var.secrets_kms_key)
          ]

        }
    ]
  })
}

#S3 Layer
resource "aws_s3_object" "layer_cryptography" {
  bucket = aws_s3_bucket.s3_api_prices_code.id
  key    = "llv-api-rfl-cryptography.zip"
  source = "../code/llv-api-rfl-cryptography.zip"  
}

resource "aws_lambda_layer_version" "llv_cryptography" {
  layer_name = format("llv-api-rfl-%s-cryptography", var.environment)
  compatible_runtimes = ["python3.9"]
  s3_bucket = aws_s3_bucket.s3_api_prices_code.bucket
  s3_key = aws_s3_object.layer_cryptography.key
}

# Creación de la Lambda
resource "aws_lambda_function" "lbd_api_rfl_token_checking" {
  filename      = data.archive_file.file_lbd_token_checking.output_path
  source_code_hash = data.archive_file.file_lbd_token_checking.output_base64sha256
  function_name = format("lbd-%s-layer-api-rfl-token-checking", var.environment)
  role          = aws_iam_role.rol_lbd_api_token_checking.arn
  handler       = "lambda_function.lambda_handler"  
  runtime       = "python3.9"
  timeout       = 5
  memory_size = 1024

  layers = [aws_lambda_layer_version.llv_cryptography.arn]
  
  vpc_config {
    subnet_ids         = var.subnet_app
    security_group_ids = [var.security_group]
  }

  environment {
    variables = {
      SECRET_AUTENTICATION_INFO = aws_secretsmanager_secret.sm_b2c.name
    }
  }
  depends_on = [ aws_iam_role_policy.irp_lbd_api_checking_token ]
}

#---------------------------------------------------------------------------
# INICIA LA CREACIÓN DEl GLUE QUE ETL PRICES EOD

# Código Fuente del glue
resource "aws_s3_object" "glue_etl_prices_eod_code" {
  bucket = aws_s3_bucket.s3_api_prices_code.bucket
  key    = "glue-api-rfl-etl-prices-eod.py"
  source = "../code/glue-api-rfl-etl-prices-eod.py"
  force_destroy = true
}

# Rol para el glue etl prices eod
resource "aws_iam_role" "rol_glue_api_etl_prices_eod" {
  name = format("rol-%s-glue-api-rfl-etl-prices-eod", var.environment)
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = "sts:AssumeRole"
            Effect = "Allow"
            Sid    = ""
            Principal = {
                Service = "glue.amazonaws.com"
            } 
        },
    ]
  })
}

# Política del Glue etl prices eod
resource "aws_iam_role_policy" "irp_glue_api_etl_prices_eod" {
  name = "policy-irp-glue-api-rfl-etl-prices-eod"
  role = aws_iam_role.rol_glue_api_etl_prices_eod.id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
        {
            Action = [
                "ec2:DescribeVpcEndpoints",
                "ec2:DescribeRouteTables",
                "ec2:CreateNetworkInterface",
                "ec2:CreateTags",
                "ec2:DeleteNetworkInterface",
                "ec2:DescribeNetworkInterfaces",
                "ec2:DescribeSecurityGroups",
                "ec2:DescribeSubnets",
                "ec2:DescribeVpcAttribute",
                "glue:GetCatalog",
                "glue:GetConnection",
                "glue:GetConnections",
                "logs:CreateLogGroup",
                "logs:CreateLogStream",
                "logs:PutLogEvents",
                "logs:DescribeLogStreams"
            ]
            Effect = "Allow"
            Resource = ["*"]
        },
        {
          Action = [
            "kms:Decrypt",
            "secretsmanager:GetSecretValue",
          ]
          Effect = "Allow"
          Resource = [
            "${aws_secretsmanager_secret.sm_mail.arn}",
            "${aws_secretsmanager_secret.sm_db.arn}",
            format("arn:aws:kms:us-east-1:%s:key/%s", data.aws_caller_identity.AccountID.account_id, var.secrets_kms_key)
          ]
        },
        {
          Action = [
            "dynamodb:BatchWriteItem",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:Query",
            "dynamodb:Scan",
            "dynamodb:DeleteItem"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_dynamodb_table.table_all_isines.arn}",
            "${aws_dynamodb_table.table_client_params.arn}",
            "${aws_dynamodb_table.table_version.arn}"
          ]
        },
        {
          Action = [
            "sqs:SendMessage",
            "sqs:GetQueueUrl" 
          ]
          Effect = "Allow"
          Resource = [
            "${aws_sqs_queue.sqs_fifo_file_gen.arn}"
          ]
        },
        {
          Action = [
            "s3:GetObject",
            "s3:ListBucket"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_s3_bucket.s3_api_prices_code.arn}",
            "${aws_s3_bucket.s3_api_prices_code.arn}/*"
          ]
        },
        {
          Action = [
            "s3:PutObject"
          ]
          Effect = "Allow"
          Resource = [
            "${aws_s3_bucket.s3_api_rfl_output.arn}",
            "${aws_s3_bucket.s3_api_rfl_output.arn}/*"
          ]
        }
    ]
  })
}

# Creación del Glue Job ETL Prices EOD
resource "aws_glue_job" "glue_api_etl_prices_eod" {
  name     = format("glue-%s-api-rfl-etl-prices-eod", var.environment)
  role_arn = aws_iam_role.rol_glue_api_etl_prices_eod.arn
  max_capacity = 1
  glue_version = "3.0"
  execution_class = "STANDARD"
  timeout = 10

  connections = var.vpc_app

  command {
    name = "pythonshell"
    script_location = "s3://${aws_s3_bucket.s3_api_prices_code.bucket}/${aws_s3_object.glue_etl_prices_eod_code.key}"
    python_version = "3.9"
  }

  execution_property {
    max_concurrent_runs = 5
  }
  default_arguments = {
    "--DATA_EXPIRATION_CO_TIME" = "15:00"
    "--DB_SECRET" = aws_secretsmanager_secret.sm_db.name
    "--EMAIL_SECRET" = aws_secretsmanager_secret.sm_mail.name
    "--GEN_FILES_SQS" = aws_sqs_queue.sqs_fifo_file_gen.name
    "--OUTPUT_BUCKET_NAME"	= aws_s3_bucket.s3_api_rfl_output.bucket
    "--OUTPUT_GENERIC_FILE_PATH" = "prices/{valuation_date}/api_rfl_prices_all_isines_{valuation_date}.json"
    "library-set" = "analytics"
    "--job-language" = "python"
  }
}

#-------------------------------------------------------------------------------------------------------
# INICIA LA CREACIÓN DEL BUCKET API RFL OUTPUT
resource "aws_s3_bucket" "s3_api_rfl_output" {
  bucket = format("s3-%s-api-rfl-output", var.environment)
}

resource "aws_s3_bucket_public_access_block" "s3_bucket_block_info" {
  bucket = aws_s3_bucket.s3_api_rfl_output.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

#-------------------------------------------------------------------------------
# INICIA LA CREACIÓN DE LAS TABLAS DYNAMO PARA LA API
resource "aws_dynamodb_table" "table_client_params" {
  name             = "dnb-api-rfl-prices-client-params"
  hash_key         = "user_id"
  billing_mode     = "PAY_PER_REQUEST"

  attribute {
    name = "user_id"
    type = "S"
  }
}

resource "aws_dynamodb_table" "table_version" {
  name             = "dnb-api-rfl-version"
  hash_key         = "product"
  range_key        = "valuation_date"
  billing_mode     = "PAY_PER_REQUEST"

  attribute {
    name = "product"
    type = "S"
  }

  attribute {
    name = "valuation_date"
    type = "S"
  }

  ttl {
    attribute_name = "expirate_at"
    enabled        = true
  }
}

resource "aws_dynamodb_table" "table_all_isines" {
  name             = "dnb-api-rfl-prices-all-isines"
  hash_key         = "isin_code"
  billing_mode     = "PAY_PER_REQUEST"

  attribute {
    name = "isin_code"
    type = "S"
  }

  ttl {
    attribute_name = "expirate_at"
    enabled        = true
  }
}

#-----------------------------------------------------------------------
# INICIA LA CREACIÓN DE LA SQS - PRICES FILE GEN

resource "aws_sqs_queue" "sqs_fifo_file_gen" {
  name                      = format("sqs-%s-api-rfl-prices-file-gen.fifo", var.environment)
  fifo_queue                  = true
  content_based_deduplication = true
  visibility_timeout_seconds = 900
}

# ASOCIAR LAMBDA A LA SQS
resource "aws_lambda_event_source_mapping" "my_mapping" {
  event_source_arn  = aws_sqs_queue.sqs_fifo_file_gen.arn
  function_name     = aws_lambda_function.lbd_api_rfl_prices_file_gen.arn
  batch_size         = 1
}

#------------------------------------------------------------------------
# INICIA LA CREACIÓN DE LA API RFL
resource "aws_api_gateway_rest_api" "agra_rfl" {
  name = format("ag-%s-rfl-clients", var.environment)
  description = "Api para el manejo de precios RFL"

  endpoint_configuration {
    types = ["REGIONAL"]
  }  
}

resource "aws_api_gateway_authorizer" "aga_lbd_layer_token_checking" {
  name                   = "aga-lp-lbd-rfl-api-layer-token-checking"
  rest_api_id            = aws_api_gateway_rest_api.agra_rfl.id
  authorizer_uri         = aws_lambda_function.lbd_api_rfl_token_checking.invoke_arn
  authorizer_result_ttl_in_seconds = 0  
}

resource "aws_lambda_permission" "lp_lbd_api_layer_token_checking" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lbd_api_rfl_token_checking.function_name
  principal     = "apigateway.amazonaws.com" 
  source_arn    = "${aws_api_gateway_rest_api.agra_rfl.execution_arn}/authorizers/${aws_api_gateway_authorizer.aga_lbd_layer_token_checking.id}" 
}

#------------------------------------------------------------------------------------------------
# Endpoint: rfl/prices/ - GET

resource "aws_api_gateway_resource" "agr_rfl_get" {  
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  parent_id   = aws_api_gateway_rest_api.agra_rfl.root_resource_id
  path_part   = "rfl"
}

resource "aws_api_gateway_resource" "agr_prices_get" {  
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  parent_id   = aws_api_gateway_resource.agr_rfl_get.id
  path_part   = "prices"
}

resource "aws_lambda_permission" "lp_lbd_api_rfl_prices_client_isines" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lbd_api_rfl_prices_client_isines.function_name
  principal     = "apigateway.amazonaws.com"
}

resource "aws_api_gateway_method" "agm_lbd_api_prices_client_isines" {  
  rest_api_id   = aws_api_gateway_rest_api.agra_rfl.id
  resource_id   = aws_api_gateway_resource.agr_prices_get.id
  http_method   = "GET"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.aga_lbd_layer_token_checking.id
}

resource "aws_api_gateway_integration" "agi_lbd_api_prices_client_isines" {  
  rest_api_id             = aws_api_gateway_rest_api.agra_rfl.id
  resource_id             = aws_api_gateway_resource.agr_prices_get.id
  http_method             = aws_api_gateway_method.agm_lbd_api_prices_client_isines.http_method
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.lbd_api_rfl_prices_client_isines.invoke_arn

  depends_on = [  
    aws_api_gateway_method.agm_lbd_api_prices_client_isines,
    aws_lambda_permission.lp_lbd_api_rfl_prices_client_isines
  ]
}

resource "aws_api_gateway_method_response" "agmr_agi_lbd_api_prices_client_isines" {
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  resource_id = aws_api_gateway_resource.agr_prices_get.id
  http_method = aws_api_gateway_method.agm_lbd_api_prices_client_isines.http_method
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }

  depends_on = [  
    aws_api_gateway_method.agm_lbd_api_prices_client_isines
  ]
}

resource "aws_api_gateway_integration_response" "agi_lbd_api_prices_client_isines" {
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  resource_id = aws_api_gateway_resource.agr_prices_get.id
  http_method = aws_api_gateway_method.agm_lbd_api_prices_client_isines.http_method
  status_code = aws_api_gateway_method_response.agmr_agi_lbd_api_prices_client_isines.status_code
  response_templates      = {
    "application/json" = ""
  }

  depends_on = [
    aws_api_gateway_method.agm_lbd_api_prices_client_isines,
    aws_api_gateway_integration.agi_lbd_api_prices_client_isines
  ]  
}

# Endpoint: config/rfl/prices - POST
resource "aws_api_gateway_resource" "agr_config" {  
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  parent_id   = aws_api_gateway_rest_api.agra_rfl.root_resource_id
  path_part   = "config"
}

resource "aws_api_gateway_resource" "agr_rfl_post" {  
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  parent_id   = aws_api_gateway_resource.agr_config.id
  path_part   = "rfl"
}

resource "aws_api_gateway_resource" "agr_prices_post" {  
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  parent_id   = aws_api_gateway_resource.agr_rfl_post.id
  path_part   = "prices"
}

resource "aws_lambda_permission" "lp_lbd_api_rfl_prices_client_params" {
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.lbd_api_rfl_prices_client_params.function_name
  principal     = "apigateway.amazonaws.com"
}

resource "aws_api_gateway_method" "agm_lbd_api_rfl_prices_client_params" {  
  rest_api_id   = aws_api_gateway_rest_api.agra_rfl.id
  resource_id   = aws_api_gateway_resource.agr_prices_post.id
  http_method   = "POST"
  authorization = "CUSTOM"
  authorizer_id = aws_api_gateway_authorizer.aga_lbd_layer_token_checking.id
}

resource "aws_api_gateway_integration" "agi_lbd_api_rfl_prices_client_params" {  
  rest_api_id             = aws_api_gateway_rest_api.agra_rfl.id
  resource_id             = aws_api_gateway_resource.agr_prices_post.id
  http_method             = aws_api_gateway_method.agm_lbd_api_rfl_prices_client_params.http_method 
  integration_http_method = "POST"
  type                    = "AWS_PROXY"
  uri                     = aws_lambda_function.lbd_api_rfl_prices_client_params.invoke_arn 

  depends_on = [  
    aws_api_gateway_method.agm_lbd_api_prices_client_isines,
    aws_lambda_permission.lp_lbd_api_rfl_prices_client_isines
  ]
}

resource "aws_api_gateway_method_response" "agmr_lbd_api_rfl_prices_client_params" {
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  resource_id = aws_api_gateway_resource.agr_prices_post.id
  http_method = aws_api_gateway_method.agm_lbd_api_rfl_prices_client_params.http_method  
  status_code = "200"

  response_models = {
    "application/json" = "Empty"
  }
  depends_on = [  
    aws_api_gateway_method.agm_lbd_api_rfl_prices_client_params
  ]
}

resource "aws_api_gateway_integration_response" "agi_lbd_api_rfl_prices_client_params" {
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id
  resource_id = aws_api_gateway_resource.agr_prices_post.id
  http_method = aws_api_gateway_method.agm_lbd_api_rfl_prices_client_params.http_method 
  status_code = aws_api_gateway_method_response.agmr_lbd_api_rfl_prices_client_params.status_code
  response_templates      = {
    "application/json" = ""
  }

  depends_on = [ 
    aws_api_gateway_method.agm_lbd_api_rfl_prices_client_params,
    aws_api_gateway_integration.agi_lbd_api_rfl_prices_client_params
  ]  
}

resource "aws_api_gateway_deployment" "agd_rfl_dep" {
  rest_api_id = aws_api_gateway_rest_api.agra_rfl.id    
  depends_on = [ 
    aws_api_gateway_integration_response.agi_lbd_api_prices_client_isines,
    aws_api_gateway_integration_response.agi_lbd_api_rfl_prices_client_params
  ] 
}

resource "aws_api_gateway_stage" "ags_intradiapp" {
  deployment_id = aws_api_gateway_deployment.agd_rfl_dep.id
  rest_api_id   = aws_api_gateway_rest_api.agra_rfl.id
  stage_name    = var.environment

  lifecycle {
    ignore_changes = [ deployment_id ]
  }

  depends_on = [
    aws_api_gateway_deployment.agd_rfl_dep
  ]  
}


#-------------------------------------------------------------------------------------
# INICIA LA CREACIÓN DEL CLOUDFRONT

data "aws_iam_policy_document" "s3_policy" {
  statement {
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.s3_api_rfl_output.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = [aws_cloudfront_origin_access_identity.coai_files.iam_arn]
    }
  }
}

resource "aws_s3_bucket_policy" "bp_policy" {
  bucket = aws_s3_bucket.s3_api_rfl_output.id
  policy = data.aws_iam_policy_document.s3_policy.json
}


resource "aws_cloudfront_origin_access_control" "coac_source_files" {
  name                              = "source_files_api_prices"
  origin_access_control_origin_type = "s3"
  signing_behavior                  = "always"
  signing_protocol                  = "sigv4"
}

resource "aws_cloudfront_cache_policy" "ccp_default" {
  name        = "s3-behavior-cache-policy-api-prices"
  comment     = "Policy para el s3 behavior"

  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0
  
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"      
    }

    headers_config {
      header_behavior = "none"      
    }

    query_strings_config {
      query_string_behavior = "none"      
    }  
  }
}

resource "aws_cloudfront_response_headers_policy" "rhp_default" {
  name    = "s3-response-headers-policy-api-prices"
  comment = "s3-response-headers-policy-api-prices" 

  cors_config {
    access_control_allow_credentials = false   

    access_control_allow_methods {      
      items = ["GET","POST", "HEAD"]    
    }

    access_control_allow_origins {
      items = ["*"]
    }

    access_control_allow_headers {      
      items = ["*"]    
    }

    origin_override = false
  }
}

resource "aws_cloudfront_cache_policy" "ccp_default_api" {
  name        = "s3-behavior-cache-policy-api-rfl"
  comment     = "Policy para el s3 behavior API Precia RFL"  

  default_ttl = 0
  max_ttl     = 0
  min_ttl     = 0
  
  parameters_in_cache_key_and_forwarded_to_origin {
    cookies_config {
      cookie_behavior = "none"      
    }

    headers_config {
      header_behavior = "none"      
    }

    query_strings_config {
      query_string_behavior = "none"      
    }  
  }
}

resource "aws_cloudfront_response_headers_policy" "rhp_default_api" {
  name    = "s3-response-headers-policy-api-rfl"
  comment = "s3-response-headers-policy-api-rfl" 

  cors_config {
    access_control_allow_credentials = false   

    access_control_allow_methods {      
      items = ["GET", "POST", "HEAD"]    
    }

    access_control_allow_origins {
      items = ["*"]
    }

    access_control_allow_headers {      
      items = ["*"]    
    }

    origin_override = false
  }
}

resource "aws_cloudfront_origin_access_identity" "coai_files" {
  comment = "Origin Access Identity S3 files to API Precia"
}

resource "aws_cloudfront_origin_request_policy" "corp_request_info_to_origin" {
  name    = "all_info_to_origin_api_prices"
  comment = "request completo viaja a api de origen"

  cookies_config {
    cookie_behavior = "all"
  }

  headers_config {
    header_behavior = "allExcept"
    headers {
      items = ["Host"]
    }
  }

  query_strings_config {
    query_string_behavior = "all"
  }
}

resource "aws_cloudfront_distribution" "s3_distribution" {
  origin {
    domain_name              = aws_s3_bucket.s3_api_rfl_output.bucket_regional_domain_name    
    origin_id                = "s3_origin"

    s3_origin_config {      
      origin_access_identity = aws_cloudfront_origin_access_identity.coai_files.cloudfront_access_identity_path      
    }
  }
  
  origin {    
    domain_name              = replace(aws_api_gateway_deployment.agd_rfl_dep.invoke_url,"/^https?://([^/]*).*/", "$1")     
    origin_id                = "api_origin"

    custom_origin_config {
      http_port              = 80
      https_port             = 443
      origin_protocol_policy = "https-only"
      origin_ssl_protocols   = ["TLSv1.2"]
	  }
  }

  enabled             = true
  is_ipv6_enabled     = true
  default_root_object = "/none-root-config/index.html"
  web_acl_id          = data.aws_wafv2_web_acl.waf.arn

  default_cache_behavior {
    allowed_methods  = ["GET", "HEAD", "OPTIONS"]
    target_origin_id = "s3_origin"
    cached_methods   = ["GET", "HEAD", "OPTIONS"]
    compress = true

    cache_policy_id = aws_cloudfront_cache_policy.ccp_default.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.rhp_default.id
    
    viewer_protocol_policy = "redirect-to-https"    
  }

  # Cache behavior with precedence 0
  ordered_cache_behavior {
    path_pattern     = format("/%s/*", var.environment)  // "/api/*"
	  allowed_methods  = ["DELETE", "GET", "HEAD", "OPTIONS", "PATCH", "POST", "PUT"]
	  cached_methods   = ["GET", "HEAD"]
	  target_origin_id = "api_origin"

	  default_ttl = 0
	  min_ttl     = 0
	  max_ttl     = 0
    
    origin_request_policy_id = aws_cloudfront_origin_request_policy.corp_request_info_to_origin.id
    
    cache_policy_id = aws_cloudfront_cache_policy.ccp_default_api.id
    response_headers_policy_id = aws_cloudfront_response_headers_policy.rhp_default_api.id    

    viewer_protocol_policy = "redirect-to-https"
  }

  price_class = "PriceClass_All"

  restrictions {
    geo_restriction {
      restriction_type = "none"
    }
  }

  viewer_certificate {
    cloudfront_default_certificate = true
  }

  custom_error_response {
    error_code = 403
    response_code = 200
    response_page_path = "/none-root-config/index.html"
  }

  comment = "Cloud Front para la API RFL"
}

################################################################################################################################
# CLI UPDATE
################################################################################################################################

locals {
  lbd_env = "{OUTPUT_BUCKET_NAME=${aws_s3_bucket.s3_api_rfl_output.bucket},OUTPUT_FILE_PATH=\"prices/{valuation_date}/api_rfl_prices_{user_id}_{valuation_date}.json\",VERSION_TABLE_NAME=${aws_dynamodb_table.table_version.name},CLIENTS_PARAMS_TABLE_NAME=${aws_dynamodb_table.table_client_params.name},EXPIRATE_SEC_TIME=900,OUTPUT_BUCKET_URL=\"https://${aws_s3_bucket.s3_api_rfl_output.id}.s3.amazonaws.com\",CLOUDFRONT_URL=\"https://${aws_cloudfront_distribution.s3_distribution.domain_name}\"}"
}

resource "null_resource" "cli_commands" {
  triggers = {
    timestamp = timestamp()
  }
  # Update lbd-%s-layer-api-rfl-prices-client-isines: Variables
  provisioner "local-exec" {
    command = "aws lambda update-function-configuration --function-name ${aws_lambda_function.lbd_api_rfl_prices_client_isines.function_name} --environment Variables=${local.lbd_env}"
  }

  depends_on = [
    aws_cloudfront_distribution.s3_distribution
  ]  
}
