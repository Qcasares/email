# SMTP Email Sender

A Python script for sending emails via SMTP with support for HTML formatting, plain text, and file attachments.

## Features

- **Multipart emails**: Sends both plain text and HTML versions
- **Attachment support**: Attach multiple files to your emails
- **Configuration-based**: All settings stored in JSON config file
- **Trusted authentication**: Works with SMTP servers that allow trusted connections (no username/password required)
- **Error handling**: Basic error handling with informative messages
- **No external dependencies**: Uses only Python standard library

## Requirements

- Python 3.6 or higher
- No external packages required (uses standard library only)

## Configuration

All email settings are stored in `email_config.json`. Edit this file to configure your email:

```json
{
  "smtp_server": "10.51.1.34",
  "smtp_port": 25,
  "from_address": "sender@example.com",
  "to_addresses": [
    "recipient1@example.com",
    "recipient2@example.com"
  ],
  "subject": "Your Email Subject",
  "body_text": "Plain text version of your email",
  "body_html": "<html><body><h1>HTML Version</h1></body></html>",
  "attachments": [
    "/path/to/file1.pdf",
    "/path/to/file2.jpg"
  ]
}
```

### Configuration Fields

| Field | Required | Description |
|-------|----------|-------------|
| `smtp_server` | Yes | SMTP server hostname or IP address |
| `smtp_port` | No | SMTP port (default: 25) |
| `from_address` | Yes | Sender email address |
| `to_addresses` | Yes | List of recipient email addresses |
| `subject` | Yes | Email subject line |
| `body_text` | No | Plain text version of email body |
| `body_html` | No | HTML version of email body |
| `attachments` | No | List of file paths to attach |

## Usage

### Basic Usage

1. Edit `email_config.json` with your email settings
2. Run the script:

```bash
python3 send_email.py
```

### Custom Configuration File

You can specify a different configuration file:

```bash
python3 send_email.py /path/to/custom_config.json
```

### Make Script Executable (Optional)

On Linux/macOS:

```bash
chmod +x send_email.py
./send_email.py
```

## Examples

### Example 1: Simple Text Email

```json
{
  "smtp_server": "10.51.1.34",
  "smtp_port": 25,
  "from_address": "noreply@company.com",
  "to_addresses": ["user@example.com"],
  "subject": "System Notification",
  "body_text": "This is a simple text email."
}
```

### Example 2: HTML Email with Multiple Recipients

```json
{
  "smtp_server": "10.51.1.34",
  "smtp_port": 25,
  "from_address": "notifications@company.com",
  "to_addresses": [
    "user1@example.com",
    "user2@example.com",
    "user3@example.com"
  ],
  "subject": "Weekly Report",
  "body_text": "Please see the attached weekly report.",
  "body_html": "<html><body><h2>Weekly Report</h2><p>Please see the <strong>attached</strong> weekly report.</p></body></html>"
}
```

### Example 3: Email with Attachments

```json
{
  "smtp_server": "10.51.1.34",
  "smtp_port": 25,
  "from_address": "reports@company.com",
  "to_addresses": ["manager@example.com"],
  "subject": "Monthly Report - January 2025",
  "body_text": "Please find attached the monthly report.",
  "body_html": "<html><body><h1>Monthly Report</h1><p>Please find attached the monthly report for January 2025.</p></body></html>",
  "attachments": [
    "/home/user/reports/january_2025.pdf",
    "/home/user/reports/charts.png"
  ]
}
```

## Error Handling

The script provides informative error messages for common issues:

- **Configuration file not found**: Check the path to `email_config.json`
- **Invalid JSON**: Verify the JSON syntax in the configuration file
- **Missing required fields**: Ensure all required fields are present
- **Attachment not found**: Check file paths in the `attachments` list
- **SMTP connection errors**: Verify SMTP server address and network connectivity
- **Connection timeout**: Check firewall settings and SMTP server availability

## Exit Codes

- `0`: Email sent successfully
- `1`: Error occurred (check error message for details)

## Troubleshooting

### Connection Refused

If you get a "Connection refused" error:
- Verify the SMTP server address and port
- Check firewall settings
- Ensure the SMTP service is running on the server

### Timeout Errors

If you get timeout errors:
- Check network connectivity
- Verify the SMTP server is accessible from your machine
- Check if any security groups or firewalls are blocking port 25

### Attachment Issues

If attachments aren't working:
- Verify file paths are absolute, not relative
- Check file permissions
- Ensure files exist at the specified paths

## Security Notes

- This script is designed for trusted SMTP servers that don't require authentication
- Be careful when hardcoding email addresses in configuration files
- Consider using environment variables for sensitive information in production
- Validate input data before sending emails

## License

This script is provided as-is for educational and internal use purposes.
