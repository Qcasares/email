#!/usr/bin/env python3
"""
SMTP Email Sender Script
Sends emails via SMTP with support for HTML, plain text, and attachments.
Configuration is loaded from email_config.json.
"""

import smtplib
import json
import sys
import ssl
import logging
import mimetypes
from email.message import EmailMessage
from pathlib import Path
from typing import Iterable


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
        config_path = Path(config_file_path).expanduser()
        with config_path.open('r', encoding='utf-8') as config_file:
            configuration = json.load(config_file)
        return configuration
    except FileNotFoundError:
        logging.error("Configuration file '%s' not found.", config_path)
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


def _unique_preserve_order(values: Iterable[str]):
    """Return a list with duplicates removed while preserving order (case-insensitive)."""
    seen = set()
    unique_values = []
    for value in values:
        normalized_value = str(value).strip()
        if not normalized_value:
            continue
        key = normalized_value.lower()
        if key in seen:
            continue
        seen.add(key)
        unique_values.append(normalized_value)
    return unique_values


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
        if body_text_path:
            text_path = Path(body_text_path).expanduser()
            if text_path.exists():
                configuration['body_text'] = text_path.read_text(encoding='utf-8')
        if body_html_path:
            html_path = Path(body_html_path).expanduser()
            if html_path.exists():
                configuration['body_html'] = html_path.read_text(encoding='utf-8')
    except Exception as body_error:
        logging.error("Failed reading body file: %s", body_error)
        return False

    return True


def create_email_message(configuration):
    """
    Create a multipart email message with text and HTML content.

    Args:
        configuration: Configuration dictionary

    Returns:
        EmailMessage: Configured email message
    """
    email_message = EmailMessage()
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

    plain_text_body = configuration.get('body_text')
    html_body = configuration.get('body_html')

    email_message.set_content(
        plain_text_body if plain_text_body else 'This is a test email.',
        charset='utf-8',
    )

    if html_body:
        email_message.add_alternative(html_body, subtype='html', charset='utf-8')

    return email_message


def attach_files(email_message, attachment_file_paths):
    """
    Attach files to the email message.

    Args:
        email_message: EmailMessage object ready for attachments
        attachment_file_paths: List of file paths to attach

    Returns:
        int: Number of successfully attached files
    """
    successfully_attached_count = 0

    for attachment_file_path in attachment_file_paths:
        try:
            attachment_path = Path(attachment_file_path).expanduser()
            if not attachment_path.is_file():
                logging.warning("Attachment file '%s' not found. Skipping.", attachment_file_path)
                continue

            mime_type, _ = mimetypes.guess_type(str(attachment_path))
            main_type, sub_type = ('application', 'octet-stream') if not mime_type else mime_type.split('/', 1)

            file_name = attachment_path.name

            if main_type == 'text':
                with attachment_path.open('r', encoding='utf-8', errors='replace') as attachment_file:
                    file_content = attachment_file.read()
                email_message.add_attachment(
                    file_content,
                    maintype=main_type,
                    subtype=sub_type,
                    filename=file_name,
                )
            else:
                with attachment_path.open('rb') as attachment_file:
                    file_content = attachment_file.read()
                email_message.add_attachment(
                    file_content,
                    maintype=main_type,
                    subtype=sub_type,
                    filename=file_name,
                )
            successfully_attached_count += 1
            logging.info("Attached: %s", file_name)

        except Exception as attachment_error:
            logging.error("Error attaching '%s': %s", attachment_file_path, attachment_error)

    return successfully_attached_count


def send_email(smtp_server_address, smtp_server_port, email_message, from_address, to_addresses, *,
               use_ssl=False, use_tls=False, username=None, password=None, timeout=10, dry_run=False):
    """
    Send email via SMTP server.

    Args:
        smtp_server_address: SMTP server hostname or IP
        smtp_server_port: SMTP server port
        email_message: EmailMessage to send
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
            context = ssl.create_default_context()
            smtp_connection = smtplib.SMTP_SSL(smtp_server_address, smtp_server_port, timeout=timeout, context=context)
        else:
            smtp_connection = smtplib.SMTP(smtp_server_address, smtp_server_port, timeout=timeout)
        smtp_connection.ehlo()

        if use_tls and not use_ssl:
            context = ssl.create_default_context()
            smtp_connection.starttls(context=context)
            smtp_connection.ehlo()

        if username and password:
            logging.debug("Authenticating as %s", username)
            smtp_connection.login(username, password)

        logging.info("Sending email...")
        smtp_connection.sendmail(from_address, to_addresses, email_message.as_string())

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
        # Load and validate configuration
        configuration = load_configuration(config_file_path)

        # Configure logging
        log_level_str = str(configuration.get('log_level', 'INFO')).upper()
        log_level = getattr(logging, log_level_str, logging.INFO)
        logging.basicConfig(level=log_level, format='%(levelname)s: %(message)s')

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

        # Attach files if specified (skip heavy I/O when dry-run)
        attachment_file_paths = configuration.get('attachments') or []
        if dry_run and attachment_file_paths:
            logging.info(
                "Dry-run enabled; skipping processing of %d attachment(s).",
                len(attachment_file_paths),
            )
        elif attachment_file_paths:
            logging.info("Processing %d attachment(s)...", len(attachment_file_paths))
            attach_files(email_message, attachment_file_paths)

        # Compute all recipients including CC and BCC
        recipients = list(configuration['to_addresses'])
        if configuration.get('cc_addresses'):
            recipients.extend(configuration['cc_addresses'])
        if configuration.get('bcc_addresses'):
            recipients.extend(configuration['bcc_addresses'])
        to_addresses = _unique_preserve_order(recipients)

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
