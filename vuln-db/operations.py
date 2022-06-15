""" Copyright start
  Copyright (C) 2008 - 2022 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

from .vulndb_api_auth import *
from connectors.core.connector import get_logger, ConnectorError
import requests

logger = get_logger('vuln-db')

errors = {
    401: 'Unauthorized',
    404: 'Invalid Path or Method',
    422: 'Invalid Parameter'
}


def make_rest_call(endpoint, method, connector_info, config, data=None, params=None):
    try:
        co = VulnDBAuth(config)
        url = co.host + endpoint
        token = co.validate_token(config, connector_info)
        logger.debug("Token: {0}".format(token))
        logger.debug("Endpoint URL: {0}".format(url))
        headers = {'Content-Type': 'application/json', 'Authorization': token}
        logger.debug("Headers: {0}".format(headers))
        response = requests.request(method, url, headers=headers, verify=co.verify_ssl, data=data, params=params)
        logger.debug("Response: {0}".format(response))
        if response.ok or response.status_code == 204:
            logger.info('Successfully got response for url {0}'.format(url))
            if 'json' in str(response.headers):
                return response.json()
            else:
                return response.content
        else:
            raise ConnectorError("{0}".format(errors.get(response.status_code)))
    except requests.exceptions.SSLError:
        raise ConnectorError('SSL certificate validation failed')
    except requests.exceptions.ConnectTimeout:
        raise ConnectorError('The request timed out while trying to connect to the server')
    except requests.exceptions.ReadTimeout:
        raise ConnectorError(
            'The server did not send any data in the allotted amount of time')
    except requests.exceptions.ConnectionError:
        raise ConnectorError('Invalid endpoint or credentials')
    except Exception as err:
        raise ConnectorError(str(err))


def build_payload(params):
    payload = {k: v for k, v in params.items() if v is not None and v != ''}
    logger.debug("Query Parameters: {0}".format(payload))
    return payload


def _check_health(config, connector_info):
    try:
        return check(config, connector_info)
    except Exception as err:
        raise ConnectorError('Invalid URL or Credentials')


def get_vuln_list(config, params, connector_info):
    try:
        endpoint = "/api/v1/vulnerabilities/find_by_date"
        payload = {
            'start_date': params.get('start_date'),
            'end_date': params.get('end_date'),
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_vuln_details(config, params, connector_info):
    try:
        filter = params.get("filter_by")
        payload = {
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        if filter == 'Vulnerability ID':
            endpoint = "/api/v1/vulnerabilities/{0}".format(params.get("vuln_id"))
        elif filter == 'Vendor ID':
            endpoint = "/api/v1/vulnerabilities/find_by_vendor_id?vendor_id={0}".format(params.get('vendor_id'))
        elif filter == 'Product ID':
            endpoint = "/api/v1/vulnerabilities/find_by_product_id?product_id={0}".format(params.get('product_id'))
        else:
            endpoint = "/api/v1/vulnerabilities/{0}/find_by_cve_id".format(params.get("cve_id"))
            payload = {}
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_vendor_details(config, params, connector_info):
    try:
        vendor = params.get('vendor')
        payload = {
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        if vendor == 'Vendor ID':
            endpoint = "/api/v1/vendors/{0}".format(params.get("vendor_id"))
        elif vendor == 'Vendor Name':
            endpoint = "/api/v1/vendors/by_name?vendor_name={0}".format(params.get("vendor_name"))
        else:
            endpoint = "/api/v1/vendors"
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_product_details(config, params, connector_info):
    try:
        vendor = params.get('vendor')
        payload = {
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        if vendor == 'Vendor ID':
            endpoint = "/api/v1/products/by_vendor_id?vendor_id={0}".format(params.get("vendor_id"))
        elif vendor == 'Vendor Name':
            endpoint = "/api/v1/products/by_vendor_name?vendor_name={0}".format(params.get("vendor_name"))
        else:
            endpoint = "/api/v1/products"
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_product_version(config, params, connector_info):
    try:
        product = params.get('product')
        payload = {
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        if product == 'Product ID':
            endpoint = "/api/v1/versions/by_product_id?product_id={0}".format(params.get("product_id"))
        else:
            endpoint = "/api/v1/versions/by_product_name?product_name={0}".format(params.get("product_name"))
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


def get_vuln_by_vendor_and_product(config, params, connector_info):
    try:
        endpoint = "/api/v1/vulnerabilities/find_by_vendor_and_product_id?vendor_id={0}&product_id={1}".format(
            params.get("vendor_id"), params.get("product_id"))
        payload = {
            'size': params.get('limit')
        }
        payload = build_payload(payload)
        response = make_rest_call(endpoint, 'GET', connector_info, config, params=payload)
        logger.debug("Response: {0}".format(response))
        return response
    except Exception as err:
        logger.exception("{0}".format(str(err)))
        raise ConnectorError("{0}".format(str(err)))


operations = {
    'get_vuln_list': get_vuln_list,
    'get_vuln_details': get_vuln_details,
    'get_vendor_details': get_vendor_details,
    'get_product_details': get_product_details,
    'get_product_version': get_product_version,
    'get_vuln_by_vendor_and_product': get_vuln_by_vendor_and_product
}
