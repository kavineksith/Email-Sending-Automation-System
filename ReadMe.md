# Email Sending Automation System

![Python Version](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

A secure, robust email sending solution for enterprise applications with advanced features and security measures.

## Features

- 🔒 **Encrypted configuration management** - Secure storage of sensitive credentials
- ✉️ **Advanced email validation** - Comprehensive email format and security checks
- 📎 **Secure attachment handling** - With size and type restrictions
- 🎨 **Template support** - With context variable injection
- ⏱️ **Scheduled email capabilities** - Send emails at specific times
- 🛡️ **Comprehensive error handling** - With detailed logging
- 📝 **Environment-based configuration** - Support for .env files
- 📊 **Logging** - Both to file and console

## Installation

1. **Prerequisites**:
   - Python 3.10 or higher
   - pip package manager

2. **Install dependencies**

3. **Set up configuration**:
   - Create a `.env` file with your environment variables
   - Initialize your encrypted `config.json` using the ConfigManager

## Usage

### Basic Email Sending

```python
from email_system import ConfigManager, SecureEmailSender

# Initialize with your config
config_manager = ConfigManager('config.json', 'email_system.key')
email_sender = SecureEmailSender(config_manager)

# Send a simple email
email_sender.send_email(
    subject="Hello from Enterprise Email System",
    body="This is a test email sent securely.",
    recipient="recipient@example.com"
)
```

### Using Templates

```python
# With template (stored in templates/ directory)
email_sender.send_email(
    subject="Your Monthly Report",
    recipient="user@example.com",
    template_name="monthly_report.html",
    template_context={
        "username": "John Doe",
        "report_data": "..."
    }
)
```

### Scheduling Emails

```python
# Schedule an email for 2:30 PM
email_sender.schedule_email(
    subject="Reminder: Team Meeting",
    body="Don't forget our 3PM team meeting!",
    recipient="team@example.com",
    schedule_time="14:30"
)

# Run the scheduler
email_sender.run_scheduled_emails()
```

### Command Line Interface

Run the CLI interface:
```bash
python email_system.py --cli
```

## Configuration

The system uses an encrypted `config.json` file. Example structure:

```json
{
    "smtp_server": "smtp.example.com",
    "smtp_port": 587,
    "smtp_username": "your_username",
    "smtp_password": "your_password",
    "default_sender": "noreply@example.com",
    "smtp_ssl": true
}
```

To create your encrypted config:

1. Set a `CONFIG_PASSPHRASE` in your environment
2. Use the `ConfigManager` to encrypt your configuration

## Security Features

- Configuration encryption using Fernet (symmetric encryption)
- Email address validation with suspicious pattern detection
- Secure attachment handling with:
  - File size limits (25MB)
  - Allowed MIME type restrictions
  - Security headers
- Template variable sanitization against XSS
- TLS 1.2+ enforced for SMTP connections

## Logging

The system logs to both file (`email_system.log`) and console with timestamps and log levels.

## Error Handling

Comprehensive error handling throughout with:
- Validation checks at each step
- Clear error messages
- Graceful failure modes

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Disclaimer

This software is provided "as is" without warranty of any kind, express or implied. The authors are not responsible for any legal implications of generated license files or repository management actions.  **This is a personal project intended for educational purposes. The developer makes no guarantees about the reliability or security of this software. Use at your own risk.**

## Disclaimer (Summarized)

This software is provided as-is without any warranties. The developers are not responsible for:
- Any misuse of this software
- Email delivery failures beyond the SMTP handoff
- Security breaches resulting from improper configuration
- Any legal implications of email content sent using this system

Users are responsible for:
- Ensuring proper configuration of SMTP settings
- Compliance with all applicable laws and regulations
- Proper security of their encryption keys and credentials