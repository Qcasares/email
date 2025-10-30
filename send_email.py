#!/usr/bin/env python3
"""
SMTP Email Sender Script
Sends emails via SMTP with support for HTML, plain text, and attachments.
Configuration is loaded from email_config.json.
"""

import smtplib
import json
import os
import sys
import ssl
import logging
import mimetypes
import base64
from typing import Optional, Tuple, List
from email import policy
from email.utils import formatdate, make_msgid
import urllib.request
import urllib.parse
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from pathlib import Path


def load_configuration(config_file_path):
    """
    Load email configuration from JSON file.

    Args:
        config_file_path: Path to the configuration JSON file

    Returns:
        dict: Configuration dictionary

    Raises:
        FileNotFoundError: If config file doesn't exist
        json.JSONDecodeError: If config file is invalid JSON
    """
    try:
        with open(config_file_path, 'r') as config_file:
            configuration = json.load(config_file)
        return configuration
    except FileNotFoundError:
        logging.error("Configuration file '%s' not found.", config_file_path)
        raise
    except json.JSONDecodeError as json_error:
        logging.error("Invalid JSON in configuration file: %s", json_error)
        raise


def _ensure_list(value):
    """
    Normalize a value to a list of strings. Accepts list or comma-separated string.

    Args:
        value: The value to normalize

    Returns:
        list[str]: Normalized list (empty list if value is falsy)
    """
    if not value:
        return []
    if isinstance(value, list):
        return [str(v).strip() for v in value if str(v).strip()]
    if isinstance(value, str):
        return [v.strip() for v in value.split(',') if v.strip()]
    return [str(value).strip()] if str(value).strip() else []


def validate_configuration(configuration):
    """
    Validate that required configuration fields are present.

    Args:
        configuration: Configuration dictionary

    Returns:
        bool: True if valid, False otherwise
    """
    required_fields = ['smtp_server', 'from_address', 'to_addresses', 'subject']

    for required_field in required_fields:
        if required_field not in configuration:
            logging.error("Missing required field '%s' in configuration.", required_field)
            return False

    to_list = _ensure_list(configuration.get('to_addresses'))
    if len(to_list) == 0:
        logging.error("'to_addresses' list cannot be empty.")
        return False

    # Normalize lists for optional fields as well
    configuration['to_addresses'] = to_list
    configuration['cc_addresses'] = _ensure_list(configuration.get('cc_addresses'))
    configuration['bcc_addresses'] = _ensure_list(configuration.get('bcc_addresses'))

    # Load body from files if provided
    body_text_path = configuration.get('body_text_file')
    body_html_path = configuration.get('body_html_file')
    try:
        if body_text_path and os.path.exists(body_text_path):
            with open(body_text_path, 'r', encoding='utf-8') as f:
                configuration['body_text'] = f.read()
        if body_html_path and os.path.exists(body_html_path):
            with open(body_html_path, 'r', encoding='utf-8') as f:
                configuration['body_html'] = f.read()
    except Exception as body_error:
        logging.error("Failed reading body file: %s", body_error)
        return False

    return True


def _build_ssl_context(verify: bool, ca_bundle: Optional[str] = None) -> ssl.SSLContext:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    if verify and ca_bundle:
        try:
            context.load_verify_locations(cafile=ca_bundle)
        except Exception as err:
            logging.warning("Failed to load CA bundle '%s': %s", ca_bundle, err)
    return context


def _fetch_oauth2_token(provider: str, config: dict) -> str:
    """
    Obtain an OAuth2 access token via refresh token flow for Gmail or Office365.

    Expected config keys:
      - Gmail: token_uri, client_id, client_secret, refresh_token
      - Office365: tenant_id, client_id, client_secret, refresh_token
    """
    provider = str(provider or '').lower()
    if provider == 'gmail':
        token_uri = config.get('token_uri', 'https://oauth2.googleapis.com/token')
        data = {
            'client_id': config.get('client_id'),
            'client_secret': config.get('client_secret'),
            'refresh_token': config.get('refresh_token'),
            'grant_type': 'refresh_token',
        }
    elif provider == 'office365' or provider == 'microsoft' or provider == 'azure' or provider == 'office':
        tenant_id = config.get('tenant_id', 'common')
        token_uri = f'https://login.microsoftonline.com/{tenant_id}/oauth2/v2.0/token'
        data = {
            'client_id': config.get('client_id'),
            'client_secret': config.get('client_secret'),
            'refresh_token': config.get('refresh_token'),
            'grant_type': 'refresh_token',
            'scope': 'https://outlook.office365.com/.default',
        }
    else:
        raise ValueError("Unsupported oauth2_provider. Use 'gmail' or 'office365'.")

    for key, val in data.items():
        if not val and key not in {'scope'}:
            raise ValueError(f"Missing OAuth2 config value: {key}")

    encoded = urllib.parse.urlencode(data).encode('utf-8')
    req = urllib.request.Request(token_uri, data=encoded, method='POST')
    req.add_header('Content-Type', 'application/x-www-form-urlencoded')
    try:
        with urllib.request.urlopen(req, timeout=int(config.get('timeout', 15))) as resp:
            payload = json.loads(resp.read().decode('utf-8'))
            access_token = payload.get('access_token')
            if not access_token:
                raise RuntimeError('No access_token in token response')
            return access_token
    except Exception as err:
        logging.error('OAuth2 token fetch failed: %s', err)
        raise


def _smtp_auth_xoauth2(smtp, email_address: str, access_token: str) -> None:
    auth_string = f"user={email_address}\x01auth=Bearer {access_token}\x01\x01".encode('utf-8')
    b64 = base64.b64encode(auth_string).decode('ascii')
    code, response = smtp.docmd('AUTH', 'XOAUTH2 ' + b64)
    if code != 235:
        raise smtplib.SMTPAuthenticationError(code, response)


def _ensure_core_headers(email_message) -> None:
    if 'Date' not in email_message:
        email_message['Date'] = formatdate(localtime=True)
    if 'Message-ID' not in email_message:
        email_message['Message-ID'] = make_msgid()


def _maybe_dkim_sign(msg_bytes: bytes, config: dict) -> bytes:
    key_path = config.get('dkim_private_key_path')
    selector = config.get('dkim_selector')
    domain = config.get('dkim_domain')
    if not (key_path and selector and domain):
        return msg_bytes
    try:
        import dkim  # type: ignore
    except Exception:
        logging.error("dkimpy not installed but DKIM config provided.")
        raise
    try:
        with open(key_path, 'rb') as f:
            privkey = f.read()
        headers = config.get('dkim_headers') or ['from', 'to', 'subject', 'date', 'message-id', 'mime-version', 'content-type']
        sig = dkim.sign(
            msg_bytes,
            selector=str(selector).encode('ascii'),
            domain=str(domain).encode('ascii'),
            privkey=privkey,
            include_headers=[h.encode('ascii') for h in headers],
        )
        return sig + msg_bytes
    except Exception as err:
        logging.error('DKIM signing failed: %s', err)
        raise
    return True


def create_email_message(configuration):
    """
    Create a multipart email message with text and HTML content.

    Args:
        configuration: Configuration dictionary

    Returns:
        MIMEMultipart: Configured email message
    """
    email_message = MIMEMultipart('mixed')
    email_message['From'] = configuration['from_address']
    email_message['To'] = ', '.join(configuration['to_addresses'])
    if configuration.get('cc_addresses'):
        email_message['Cc'] = ', '.join(configuration['cc_addresses'])
    if configuration.get('reply_to'):
        email_message['Reply-To'] = configuration['reply_to']
    email_message['Subject'] = configuration['subject']

    # Custom headers
    custom_headers = configuration.get('headers', {})
    if isinstance(custom_headers, dict):
        for header_name, header_value in custom_headers.items():
            if header_name.lower() in {'from', 'to', 'cc', 'bcc', 'subject', 'reply-to'}:
                continue
            email_message[header_name] = str(header_value)

    # Build alternative part for text and html
    alternative_part = MIMEMultipart('alternative')

    plain_text_body = configuration.get('body_text', '')
    html_body = configuration.get('body_html', '')

    if plain_text_body:
        alternative_part.attach(MIMEText(plain_text_body, 'plain', _charset='utf-8'))
    if html_body:
        alternative_part.attach(MIMEText(html_body, 'html', _charset='utf-8'))
    if not plain_text_body and not html_body:
        alternative_part.attach(MIMEText('This is a test email.', 'plain', _charset='utf-8'))

    email_message.attach(alternative_part)

    return email_message


def attach_files(email_message, attachment_file_paths):
    """
    Attach files to the email message.

    Args:
        email_message: MIMEMultipart message object
        attachment_file_paths: List of file paths to attach

    Returns:
        int: Number of successfully attached files
    """
    successfully_attached_count = 0

    for attachment_file_path in attachment_file_paths:
        try:
            if not os.path.exists(attachment_file_path):
                print(f"Warning: Attachment file '{attachment_file_path}' not found. Skipping.")
                continue

            mime_type, _ = mimetypes.guess_type(attachment_file_path)
            main_type, sub_type = ('application', 'octet-stream') if not mime_type else mime_type.split('/', 1)

            file_name = os.path.basename(attachment_file_path)

            if main_type == 'text':
                with open(attachment_file_path, 'r', encoding='utf-8', errors='ignore') as attachment_file:
                    file_content = attachment_file.read()
                part = MIMEText(file_content, _subtype=sub_type, _charset='utf-8')
            else:
                with open(attachment_file_path, 'rb') as attachment_file:
                    file_content = attachment_file.read()
                part = MIMEBase(main_type, sub_type)
                part.set_payload(file_content)
                encoders.encode_base64(part)

            part.add_header('Content-Disposition', f'attachment; filename="{file_name}"')
            email_message.attach(part)
            successfully_attached_count += 1
            logging.info("Attached: %s", file_name)

        except Exception as attachment_error:
            logging.error("Error attaching '%s': %s", attachment_file_path, attachment_error)

    return successfully_attached_count


def send_email(smtp_server_address, smtp_server_port, email_message, from_address, to_addresses, *,
               use_ssl=False, use_tls=False, username=None, password=None, timeout=10, dry_run=False,
               auth_method: Optional[str]=None, oauth2_provider: Optional[str]=None, oauth2: Optional[dict]=None,
               require_tls: bool=False, smtp_ssl_verify: bool=True, ca_bundle: Optional[str]=None,
               dkim_config: Optional[dict]=None):
    """
    Send email via SMTP server.

    Args:
        smtp_server_address: SMTP server hostname or IP
        smtp_server_port: SMTP server port
        email_message: MIMEMultipart message to send
        from_address: Sender email address
        to_addresses: List of recipient email addresses

    Returns:
        bool: True if successful, False otherwise
    """
    try:
        if dry_run:
            logging.info("Dry-run enabled. Skipping send. To: %s | Subject: %s", ', '.join(to_addresses), email_message.get('Subject'))
            return True

        logging.info("Connecting to SMTP server %s:%s...", smtp_server_address, smtp_server_port)

        if use_ssl:
            context = _build_ssl_context(smtp_ssl_verify, ca_bundle)
            smtp_connection = smtplib.SMTP_SSL(smtp_server_address, smtp_server_port, timeout=timeout, context=context)
        else:
            smtp_connection = smtplib.SMTP(smtp_server_address, smtp_server_port, timeout=timeout)
        smtp_connection.ehlo()

        if use_tls and not use_ssl:
            if require_tls and not smtp_connection.has_extn('starttls'):
                raise smtplib.SMTPException('Server does not support STARTTLS but require_tls is set')
            context = _build_ssl_context(smtp_ssl_verify, ca_bundle)
            if smtp_connection.has_extn('starttls'):
                smtp_connection.starttls(context=context)
                smtp_connection.ehlo()
            elif require_tls:
                raise smtplib.SMTPException('STARTTLS was required but not initiated')

        # Authentication
        method = (auth_method or '').lower()
        if method == 'oauth2' and oauth2_provider:
            email_addr = from_address
            access_token = _fetch_oauth2_token(oauth2_provider, oauth2 or {})
            _smtp_auth_xoauth2(smtp_connection, email_addr, access_token)
        elif username and password:
            logging.debug("Authenticating as %s", username)
            smtp_connection.login(username, password)

        # Ensure core headers and generate bytes under SMTP policy
        _ensure_core_headers(email_message)
        msg_bytes = email_message.as_bytes(policy=policy.SMTP)

        # DKIM sign if configured
        if dkim_config:
            msg_bytes = _maybe_dkim_sign(msg_bytes, dkim_config)

        logging.info("Sending email...")
        smtp_connection.sendmail(from_address, to_addresses, msg_bytes)

        smtp_connection.quit()
        logging.info("Email sent successfully!")
        return True

    except smtplib.SMTPException as smtp_error:
        logging.error("SMTP Error: %s", smtp_error)
        return False
    except ConnectionRefusedError:
        logging.error("Connection refused to %s:%s", smtp_server_address, smtp_server_port)
        return False
    except TimeoutError:
        logging.error("Connection timeout to %s:%s", smtp_server_address, smtp_server_port)
        return False
    except Exception as general_error:
        logging.error("Error sending email: %s", general_error)
        return False


def main():
    """
    Main function to orchestrate email sending process.
    """
    config_file_path = 'email_config.json'

    # Allow custom config file path as command-line argument
    if len(sys.argv) > 1:
        config_file_path = sys.argv[1]

    try:
        # Configure default logging BEFORE loading config so early errors are visible
        logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

        # Load and validate configuration
        configuration = load_configuration(config_file_path)

        # Adjust log level based on config without reinitializing handlers
        log_level_str = str(configuration.get('log_level', 'INFO')).upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.getLogger().setLevel(log_level)

        if not validate_configuration(configuration):
            sys.exit(1)

        # Get SMTP settings with defaults
        smtp_server_address = configuration['smtp_server']

        # Security and ports
        use_ssl = bool(configuration.get('use_ssl', False))
        use_tls = bool(configuration.get('use_tls', False))
        if 'smtp_port' in configuration:
            smtp_server_port = configuration.get('smtp_port')
        else:
            smtp_server_port = 465 if use_ssl else (587 if use_tls else 25)

        timeout = int(configuration.get('timeout', 10))
        dry_run = bool(configuration.get('dry_run', False))

        # Create email message
        email_message = create_email_message(configuration)

        # Attach files if specified
        attachment_file_paths = configuration.get('attachments', [])
        if attachment_file_paths:
            logging.info("Processing %d attachment(s)...", len(attachment_file_paths))
            attach_files(email_message, attachment_file_paths)

        # Compute all recipients including CC and BCC
        to_addresses = list(configuration['to_addresses'])
        if configuration.get('cc_addresses'):
            to_addresses.extend(configuration['cc_addresses'])
        if configuration.get('bcc_addresses'):
            to_addresses.extend(configuration['bcc_addresses'])

        # Send email
        send_success = send_email(
            smtp_server_address,
            smtp_server_port,
            email_message,
            configuration['from_address'],
            to_addresses,
            use_ssl=use_ssl,
            use_tls=use_tls,
            username=configuration.get('smtp_username'),
            password=configuration.get('smtp_password'),
            timeout=timeout,
            dry_run=dry_run,
        )

        if send_success:
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as main_error:
        logging.error("Fatal error: %s", main_error)
        sys.exit(1)


if __name__ == "__main__":
    main()
