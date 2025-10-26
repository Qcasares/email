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
        print(f"Error: Configuration file '{config_file_path}' not found.")
        raise
    except json.JSONDecodeError as json_error:
        print(f"Error: Invalid JSON in configuration file: {json_error}")
        raise


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
            print(f"Error: Missing required field '{required_field}' in configuration.")
            return False

    if not isinstance(configuration['to_addresses'], list):
        print("Error: 'to_addresses' must be a list.")
        return False

    if len(configuration['to_addresses']) == 0:
        print("Error: 'to_addresses' list cannot be empty.")
        return False

    return True


def create_email_message(configuration):
    """
    Create a multipart email message with text and HTML content.

    Args:
        configuration: Configuration dictionary

    Returns:
        MIMEMultipart: Configured email message
    """
    email_message = MIMEMultipart('alternative')
    email_message['From'] = configuration['from_address']
    email_message['To'] = ', '.join(configuration['to_addresses'])
    email_message['Subject'] = configuration['subject']

    # Add plain text version
    plain_text_body = configuration.get('body_text', '')
    if plain_text_body:
        plain_text_part = MIMEText(plain_text_body, 'plain')
        email_message.attach(plain_text_part)

    # Add HTML version
    html_body = configuration.get('body_html', '')
    if html_body:
        html_part = MIMEText(html_body, 'html')
        email_message.attach(html_part)

    # If neither text nor HTML is provided, use a default message
    if not plain_text_body and not html_body:
        default_message = MIMEText('This is a test email.', 'plain')
        email_message.attach(default_message)

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

            with open(attachment_file_path, 'rb') as attachment_file:
                file_content = attachment_file.read()

            attachment_part = MIMEBase('application', 'octet-stream')
            attachment_part.set_payload(file_content)
            encoders.encode_base64(attachment_part)

            file_name = os.path.basename(attachment_file_path)
            attachment_part.add_header(
                'Content-Disposition',
                f'attachment; filename= {file_name}'
            )

            email_message.attach(attachment_part)
            successfully_attached_count += 1
            print(f"Attached: {file_name}")

        except Exception as attachment_error:
            print(f"Error attaching '{attachment_file_path}': {attachment_error}")

    return successfully_attached_count


def send_email(smtp_server_address, smtp_server_port, email_message, from_address, to_addresses):
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
        print(f"Connecting to SMTP server {smtp_server_address}:{smtp_server_port}...")

        smtp_connection = smtplib.SMTP(smtp_server_address, smtp_server_port, timeout=10)
        smtp_connection.ehlo()

        print("Sending email...")
        smtp_connection.sendmail(from_address, to_addresses, email_message.as_string())

        smtp_connection.quit()
        print("Email sent successfully!")
        return True

    except smtplib.SMTPException as smtp_error:
        print(f"SMTP Error: {smtp_error}")
        return False
    except ConnectionRefusedError:
        print(f"Error: Connection refused to {smtp_server_address}:{smtp_server_port}")
        return False
    except TimeoutError:
        print(f"Error: Connection timeout to {smtp_server_address}:{smtp_server_port}")
        return False
    except Exception as general_error:
        print(f"Error sending email: {general_error}")
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

        if not validate_configuration(configuration):
            sys.exit(1)

        # Get SMTP settings with defaults
        smtp_server_address = configuration['smtp_server']
        smtp_server_port = configuration.get('smtp_port', 25)

        # Create email message
        email_message = create_email_message(configuration)

        # Attach files if specified
        attachment_file_paths = configuration.get('attachments', [])
        if attachment_file_paths:
            print(f"Processing {len(attachment_file_paths)} attachment(s)...")
            attach_files(email_message, attachment_file_paths)

        # Send email
        send_success = send_email(
            smtp_server_address,
            smtp_server_port,
            email_message,
            configuration['from_address'],
            configuration['to_addresses']
        )

        if send_success:
            sys.exit(0)
        else:
            sys.exit(1)

    except Exception as main_error:
        print(f"Fatal error: {main_error}")
        sys.exit(1)


if __name__ == "__main__":
    main()
