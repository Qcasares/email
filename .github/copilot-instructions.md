# Copilot Instructions for SMTP Email Sender

## Project Overview
This is a single-purpose Python utility for sending emails via SMTP servers. It's designed for internal/trusted networks where authentication isn't required. The architecture prioritizes simplicity and reliability over complexity.

## Key Architecture Patterns

### Configuration-Driven Design
- All email settings live in `email_config.json` - never hardcode SMTP settings in code
- Configuration validation happens before any email processing begins
- Default values: SMTP port 25, no authentication required
- Support for custom config file via command line: `python send_email.py custom_config.json`

### Email Structure Pattern
```python
# Always use MIMEMultipart('alternative') for text + HTML emails
email_message = MIMEMultipart('alternative')
# Order matters: attach plain text first, then HTML
email_message.attach(MIMEText(plain_text, 'plain'))
email_message.attach(MIMEText(html_content, 'html'))
```

### Error Handling Strategy
- **Fail fast**: Validate configuration before attempting SMTP connection
- **Graceful degradation**: Skip missing attachments with warnings, don't fail entire email
- **Specific error messages**: Distinguish between connection refused, timeout, and SMTP protocol errors
- **Exit codes**: 0 for success, 1 for any failure

## Critical Implementation Details

### SMTP Connection Pattern
```python
# Always set timeout and use ehlo() for server capability detection
smtp_connection = smtplib.SMTP(server, port, timeout=10)
smtp_connection.ehlo()  # Essential for compatibility
```

### Attachment Handling
- Use `MIMEBase('application', 'octet-stream')` for all file types
- Always encode with `encoders.encode_base64()`
- Extract filename with `os.path.basename()` for Content-Disposition header
- Check file existence with `os.path.exists()` before processing

### Configuration Schema
Required fields: `smtp_server`, `from_address`, `to_addresses`, `subject`
Optional fields: `smtp_port` (default: 25), `body_text`, `body_html`, `attachments`

## Development Workflow

### Testing Email Functionality
```bash
# Test with default config
python3 send_email.py

# Test with custom config
python3 send_email.py test_config.json

# Make executable for repeated testing
chmod +x send_email.py
./send_email.py
```

### Common Configuration Scenarios
- **Internal notifications**: Use plain text only, minimal config
- **HTML reports**: Include both `body_text` and `body_html` for client compatibility
- **File distribution**: Use `attachments` array with absolute file paths

## Network Environment Assumptions
- Designed for internal SMTP servers (like `10.51.1.34`)
- No authentication mechanism implemented
- Firewall-friendly: uses standard SMTP ports (25, 587)
- 10-second connection timeout for network reliability

## Debugging Common Issues
- **"Connection refused"**: Check SMTP server address and firewall rules
- **"Timeout"**: Verify network connectivity and server availability  
- **Missing attachments**: Ensure absolute file paths and file permissions
- **JSON errors**: Validate configuration syntax before running

## Code Conventions
- Use descriptive function names that indicate return values (`validate_configuration` returns bool)
- Separate concerns: configuration loading, validation, message creation, and sending
- Print progress messages for long operations (SMTP connection, file attachments)
- Handle exceptions at the appropriate level (file-level in `attach_files`, connection-level in `send_email`)