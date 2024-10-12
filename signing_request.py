import requests
from requests_aws4auth import AWS4Auth
import boto3
import argparse
import sys

def parse_arguments():
    parser = argparse.ArgumentParser(
        description="Script para realizar una solicitud HTTP a un endpoint de API Gateway autenticado con AWS IAM",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument('-u', '--url', required=True,
                        help="URL del endpoint de API Gateway")
    
    parser.add_argument('-p', '--profile', required=True,
                        help="Perfil de AWS para obtener las credenciales")
    
    parser.add_argument('-s', '--service', default='execute-api',
                        help="Servicio de AWS (ejemplo: execute-api, s3)")
    
    parser.add_argument('-r', '--region', default='us-east-1',
                        help="Región de AWS (ejemplo: us-east-1, eu-west-1)")

    parser.add_argument('-m', '--method', default='GET',
                        help="Método HTTP a utilizar para la solicitud (default: GET)")

    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    return parser.parse_args()

def get_aws_credentials(profile):
    session = boto3.Session(profile_name=profile)
    credentials = session.get_credentials()
    return credentials

def configure_auth(credentials, region, service):
    access_key = credentials.access_key
    secret_key = credentials.secret_key
    session_token = credentials.token  # Puede ser None si no hay token de sesión

    if session_token:
        return AWS4Auth(access_key, secret_key, region, service, session_token=session_token)
    else:
        return AWS4Auth(access_key, secret_key, region, service)

def make_request(url, auth, method):
    method_dict = {
        'GET': requests.get,
        'POST': requests.post,
        'PUT': requests.put,
        'DELETE': requests.delete
    }

    method_func = method_dict.get(method)
    if method_func:
        response = method_func(url, auth=auth)
    else:
        raise ValueError(f"Unsupported method: {method}")

    return response.text

# Función principal
def main():
    args = parse_arguments()  
    
    credentials = get_aws_credentials(args.profile)  
    auth = configure_auth(credentials, args.region, args.service)  
    response = make_request(args.url, auth, args.method)  
    print(response)  


if __name__ == "__main__":
    main()
