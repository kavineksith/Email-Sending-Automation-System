"""
Enterprise Email Sending System
===============================

A secure, robust email sending solution with:
- Encrypted configuration management
- Advanced email validation
- Secure attachment handling
- Template support
- Scheduled email capabilities
- Comprehensive error handling
- Logging
- Environment-based configuration
"""

import os
import sys
import json
import re
import smtplib
import ssl
import logging
import schedule
import time
from datetime import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.base import MIMEBase
from email import encoders
from cryptography.fernet import Fernet
from typing import List, Optional, Dict, Union
from dotenv import load_dotenv
import hashlib
import hmac

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('email_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

# Load environment variables
load_dotenv()


class ConfigManager:
    """
    Secure configuration management with encryption
    """
    def __init__(self, config_path: str = 'config.json', key_path: str = 'email_system.key'):
        self.config_path = config_path
        self.key_path = key_path
        self.config = None
        self._validate_paths()
        
    def _validate_paths(self) -> None:
        """Validate configuration and key file paths"""
        if not os.path.exists(self.config_path):
            raise FileNotFoundError(f"Configuration file not found at {self.config_path}")
        if not os.path.exists(self.key_path):
            self._generate_key()
    
    def _generate_key(self) -> None:
        """Generate and save a new encryption key"""
        try:
            key = Fernet.generate_key()
            with open(self.key_path, 'wb') as key_file:
                key_file.write(key)
            logger.info("New encryption key generated and saved")
        except Exception as e:
            logger.error(f"Failed to generate encryption key: {e}")
            raise
    
    def _get_encryption_key(self) -> bytes:
        """Retrieve the encryption key"""
        try:
            with open(self.key_path, 'rb') as key_file:
                return key_file.read()
        except Exception as e:
            logger.error(f"Failed to read encryption key: {e}")
            raise
    
    def load_config(self) -> Dict:
        """Load and decrypt the configuration"""
        try:
            # Get passphrase from environment with fallback
            passphrase = os.getenv('CONFIG_PASSPHRASE', '').encode()
            if not passphrase:
                logger.warning("Using default passphrase - recommend setting CONFIG_PASSPHRASE in environment")
                passphrase = b'default_enterprise_passphrase'
            
            # Derive a key from passphrase using HKDF
            derived_key = self._derive_key(passphrase)
            fernet = Fernet(derived_key)
            
            with open(self.config_path, 'rb') as config_file:
                encrypted_data = config_file.read()
            
            decrypted_data = fernet.decrypt(encrypted_data).decode('utf-8')
            self.config = json.loads(decrypted_data)
            return self.config
        except Exception as e:
            logger.error(f"Failed to load configuration: {e}")
            raise
    
    def _derive_key(self, passphrase: bytes, salt: bytes = b'email_system_salt') -> bytes:
        """Derive a secure key from passphrase using HKDF"""
        # Using SHA-256 as the hash function
        return hashlib.pbkdf2_hmac('sha256', passphrase, salt, 100000)
    
    def update_config(self, new_config: Dict) -> None:
        """Update and encrypt the configuration"""
        try:
            passphrase = os.getenv('CONFIG_PASSPHRASE', b'default_enterprise_passphrase')
            derived_key = self._derive_key(passphrase)
            fernet = Fernet(derived_key)
            
            encrypted_data = fernet.encrypt(json.dumps(new_config).encode('utf-8'))
            
            # Create backup of old config
            if os.path.exists(self.config_path):
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup_path = f"{self.config_path}.bak_{timestamp}"
                os.rename(self.config_path, backup_path)
                logger.info(f"Created backup of config at {backup_path}")
            
            with open(self.config_path, 'wb') as config_file:
                config_file.write(encrypted_data)
            
            self.config = new_config
            logger.info("Configuration updated successfully")
        except Exception as e:
            logger.error(f"Failed to update configuration: {e}")
            raise


class EmailValidator:
    """
    Comprehensive email validation and security checks
    """
    @staticmethod
    def is_valid_email(email: str) -> bool:
        """Validate email format and domain"""
        if not email or not isinstance(email, str):
            return False
        
        # Regular expression for RFC 5322 compliant email validation
        pattern = r"(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)"
        if not re.match(pattern, email):
            return False
        
        # Additional checks
        if EmailValidator._has_suspicious_pattern(email):
            return False
        
        return True
    
    @staticmethod
    def _has_suspicious_pattern(email: str) -> bool:
        """Check for potentially malicious patterns"""
        suspicious_patterns = [
            r"\b(admin|root|administrator)\b",
            r"\.(exe|js|bat|cmd|sh|php|py|pl)\b",
            r"\s",
            r"\.\.+",
            r"--+",
            r"\/\/+"
        ]
        
        for pattern in suspicious_patterns:
            if re.search(pattern, email, re.IGNORECASE):
                return True
        return False
    
    @staticmethod
    def validate_emails(*emails: str) -> bool:
        """Validate multiple email addresses"""
        return all(EmailValidator.is_valid_email(email) for email in emails)


class AttachmentHandler:
    """
    Secure attachment handling with validation
    """
    MAX_ATTACHMENT_SIZE = 25 * 1024 * 1024  # 25MB
    ALLOWED_MIME_TYPES = {
        'pdf': 'application/pdf',
        'doc': 'application/msword',
        'docx': 'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
        'xls': 'application/vnd.ms-excel',
        'xlsx': 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
        'ppt': 'application/vnd.ms-powerpoint',
        'pptx': 'application/vnd.openxmlformats-officedocument.presentationml.presentation',
        'txt': 'text/plain',
        'csv': 'text/csv',
        'jpg': 'image/jpeg',
        'jpeg': 'image/jpeg',
        'png': 'image/png',
        'gif': 'image/gif'
    }
    
    @staticmethod
    def validate_attachment(file_path: str) -> bool:
        """Validate attachment file"""
        try:
            # Check file existence
            if not os.path.exists(file_path):
                logger.error(f"Attachment file not found: {file_path}")
                return False
            
            # Check file size
            file_size = os.path.getsize(file_path)
            if file_size > AttachmentHandler.MAX_ATTACHMENT_SIZE:
                logger.error(f"Attachment too large: {file_size} bytes")
                return False
            
            # Check file extension
            ext = os.path.splitext(file_path)[1][1:].lower()
            if ext not in AttachmentHandler.ALLOWED_MIME_TYPES:
                logger.error(f"Unsupported file type: {ext}")
                return False
            
            return True
        except Exception as e:
            logger.error(f"Attachment validation failed: {e}")
            return False
    
    @staticmethod
    def create_attachment_part(file_path: str) -> Optional[MIMEBase]:
        """Create a MIME attachment part with security checks"""
        if not AttachmentHandler.validate_attachment(file_path):
            return None
        
        try:
            ext = os.path.splitext(file_path)[1][1:].lower()
            mime_type = AttachmentHandler.ALLOWED_MIME_TYPES.get(ext, 'application/octet-stream')
            
            with open(file_path, 'rb') as file:
                part = MIMEBase(mime_type.split('/')[0], mime_type.split('/')[1])
                part.set_payload(file.read())
            
            encoders.encode_base64(part)
            filename = os.path.basename(file_path)
            part.add_header('Content-Disposition', f'attachment; filename="{filename}"')
            
            # Add security headers
            part.add_header('X-Content-Type-Options', 'nosniff')
            part.add_header('X-Download-Options', 'noopen')
            
            return part
        except Exception as e:
            logger.error(f"Failed to create attachment part: {e}")
            return None


class EmailTemplate:
    """
    Email template management with secure rendering
    """
    def __init__(self, template_dir: str = 'templates'):
        self.template_dir = template_dir
        if not os.path.exists(template_dir):
            os.makedirs(template_dir)
            logger.info(f"Created template directory at {template_dir}")
    
    def load_template(self, template_name: str, context: Dict = None) -> Optional[str]:
        """Load and render a template with context"""
        template_path = os.path.join(self.template_dir, template_name)
        
        if not os.path.exists(template_path):
            logger.error(f"Template not found: {template_path}")
            return None
        
        try:
            with open(template_path, 'r', encoding='utf-8') as file:
                content = file.read()
            
            if context:
                for key, value in context.items():
                    placeholder = f'{{{{{key}}}}}'
                    if isinstance(value, str):
                        # Basic XSS protection
                        value = self._sanitize_input(value)
                    content = content.replace(placeholder, str(value))
            
            return content
        except Exception as e:
            logger.error(f"Failed to load template: {e}")
            return None
    
    @staticmethod
    def _sanitize_input(input_str: str) -> str:
        """Basic XSS protection for template variables"""
        return input_str.replace('<', '&lt;').replace('>', '&gt;')


class SecureEmailSender:
    """
    Main email sending class with enterprise-grade security features
    """
    def __init__(self, config_manager: ConfigManager):
        self.config = config_manager.load_config()
        self.template_manager = EmailTemplate()
        self._validate_smtp_config()
    
    def _validate_smtp_config(self) -> None:
        """Validate SMTP configuration"""
        required_keys = ['smtp_server', 'smtp_port', 'smtp_username', 'smtp_password']
        for key in required_keys:
            if key not in self.config:
                raise ValueError(f"Missing required SMTP configuration: {key}")
        
        if not EmailValidator.is_valid_email(self.config.get('default_sender')):
            logger.warning("Default sender email in config is not valid")
    
    def _create_secure_context(self) -> ssl.SSLContext:
        """Create a secure SSL context"""
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_mode = ssl.CERT_REQUIRED
        return context
    
    def _connect_to_smtp_server(self) -> smtplib.SMTP:
        """Establish a secure connection to the SMTP server"""
        try:
            context = self._create_secure_context()
            
            if self.config.get('smtp_ssl', True):
                server = smtplib.SMTP_SSL(
                    host=self.config['smtp_server'],
                    port=self.config['smtp_port'],
                    context=context,
                    timeout=10
                )
            else:
                server = smtplib.SMTP(
                    host=self.config['smtp_server'],
                    port=self.config['smtp_port'],
                    timeout=10
                )
                server.starttls(context=context)
            
            # Authenticate
            server.login(
                user=self.config['smtp_username'],
                password=self.config['smtp_password']
            )
            
            return server
        except Exception as e:
            logger.error(f"SMTP connection failed: {e}")
            raise
    
    def send_email(
        self,
        subject: str,
        body: str,
        recipient: Union[str, List[str]],
        sender: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        template_name: Optional[str] = None,
        template_context: Optional[Dict] = None,
        cc: Optional[Union[str, List[str]]] = None,
        bcc: Optional[Union[str, List[str]]] = None
    ) -> bool:
        """
        Send an email with comprehensive features and security checks
        
        Args:
            subject: Email subject
            body: Email body text (ignored if template is provided)
            recipient: Single or list of recipient email addresses
            sender: Sender email address (uses config default if None)
            attachments: List of file paths to attach
            template_name: Name of template file to use
            template_context: Context variables for template
            cc: CC recipients
            bcc: BCC recipients
        
        Returns:
            bool: True if email was sent successfully, False otherwise
        """
        try:
            # Validate inputs
            sender = sender or self.config.get('default_sender')
            if not EmailValidator.is_valid_email(sender):
                raise ValueError("Invalid sender email address")
            
            # Process recipients
            if isinstance(recipient, str):
                recipients = [recipient]
            else:
                recipients = recipient
            
            if not all(EmailValidator.is_valid_email(r) for r in recipients):
                raise ValueError("Invalid recipient email address")
            
            # Process CC/BCC
            cc_list = [cc] if isinstance(cc, str) else (cc or [])
            bcc_list = [bcc] if isinstance(bcc, str) else (bcc or [])
            
            all_recipients = recipients + cc_list + bcc_list
            if not all(EmailValidator.is_valid_email(r) for r in all_recipients):
                raise ValueError("Invalid CC/BCC email address")
            
            # Create message
            msg = MIMEMultipart()
            msg['From'] = sender
            msg['To'] = ', '.join(recipients)
            msg['Subject'] = subject
            
            if cc_list:
                msg['Cc'] = ', '.join(cc_list)
            
            # Add body - either from template or direct
            if template_name:
                body = self.template_manager.load_template(template_name, template_context)
                if body is None:
                    raise ValueError("Failed to load email template")
                msg.attach(MIMEText(body, 'html'))
            else:
                msg.attach(MIMEText(body, 'plain'))
            
            # Add attachments
            if attachments:
                for attachment in attachments:
                    part = AttachmentHandler.create_attachment_part(attachment)
                    if part:
                        msg.attach(part)
                    else:
                        logger.warning(f"Skipping invalid attachment: {attachment}")
            
            # Send email
            with self._connect_to_smtp_server() as server:
                server.sendmail(
                    from_addr=sender,
                    to_addrs=all_recipients,
                    msg=msg.as_string()
                )
            
            logger.info(f"Email sent successfully to {recipients}")
            return True
        except Exception as e:
            logger.error(f"Failed to send email: {e}")
            return False
    
    def schedule_email(
        self,
        subject: str,
        body: str,
        recipient: Union[str, List[str]],
        schedule_time: str,
        sender: Optional[str] = None,
        attachments: Optional[List[str]] = None,
        template_name: Optional[str] = None,
        template_context: Optional[Dict] = None,
        cc: Optional[Union[str, List[str]]] = None,
        bcc: Optional[Union[str, List[str]]] = None
    ) -> None:
        """
        Schedule an email to be sent at a specific time
        
        Args:
            schedule_time: Time in format "HH:MM" or cron-like string
            Other args same as send_email
        """
        try:
            # Validate schedule time
            if not re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', schedule_time):
                raise ValueError("Invalid schedule time format. Use 'HH:MM'")
            
            # Create a closure with the email parameters
            def send_scheduled_email():
                self.send_email(
                    subject=subject,
                    body=body,
                    recipient=recipient,
                    sender=sender,
                    attachments=attachments,
                    template_name=template_name,
                    template_context=template_context,
                    cc=cc,
                    bcc=bcc
                )
            
            # Schedule the email
            schedule.every().day.at(schedule_time).do(send_scheduled_email)
            logger.info(f"Email scheduled to be sent at {schedule_time}")
        except Exception as e:
            logger.error(f"Failed to schedule email: {e}")
            raise
    
    def run_scheduled_emails(self) -> None:
        """Run the scheduler for pending emails"""
        try:
            logger.info("Starting email scheduler...")
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Email scheduler stopped by user")
        except Exception as e:
            logger.error(f"Email scheduler failed: {e}")
            raise


class EmailSystemCLI:
    """
    Command-line interface for the email system
    """
    @staticmethod
    def get_input(prompt: str, required: bool = True, validator=None) -> str:
        """Get user input with validation"""
        while True:
            try:
                value = input(prompt).strip()
                if required and not value:
                    print("This field is required.")
                    continue
                if validator and not validator(value):
                    print("Invalid input. Please try again.")
                    continue
                return value
            except KeyboardInterrupt:
                print("\nOperation cancelled by user.")
                sys.exit(0)
    
    @staticmethod
    def run() -> None:
        """Run the CLI interface"""
        print("\nEnterprise Email System\n" + "="*30)
        
        try:
            # Initialize config manager
            config_path = os.getenv('EMAIL_CONFIG_PATH', 'config.json')
            key_path = os.getenv('EMAIL_KEY_PATH', 'email_system.key')
            
            config_manager = ConfigManager(config_path, key_path)
            email_sender = SecureEmailSender(config_manager)
            
            # Main menu
            while True:
                print("\nOptions:")
                print("1. Send email now")
                print("2. Schedule email")
                print("3. Run scheduled emails")
                print("4. Exit")
                
                choice = input("Enter your choice (1-4): ").strip()
                
                if choice == '1':
                    EmailSystemCLI._send_email_now(email_sender)
                elif choice == '2':
                    EmailSystemCLI._schedule_email(email_sender)
                elif choice == '3':
                    email_sender.run_scheduled_emails()
                elif choice == '4':
                    print("Exiting...")
                    break
                else:
                    print("Invalid choice. Please try again.")
        except Exception as e:
            logger.error(f"CLI error: {e}")
            print(f"An error occurred: {e}")
            sys.exit(1)
    
    @staticmethod
    def _send_email_now(email_sender: SecureEmailSender) -> None:
        """Handle immediate email sending"""
        print("\nSend Email Now\n" + "-"*20)
        
        sender = EmailSystemCLI.get_input(
            "Sender email [leave blank for default]: ",
            required=False,
            validator=EmailValidator.is_valid_email
        )
        
        recipient = EmailSystemCLI.get_input(
            "Recipient email(s), comma-separated: ",
            validator=lambda x: all(EmailValidator.is_valid_email(e.strip()) for e in x.split(','))
        )
        
        subject = EmailSystemCLI.get_input("Subject: ")
        body = EmailSystemCLI.get_input("Body: ")
        
        attachments = []
        while True:
            attachment = EmailSystemCLI.get_input(
                "Attachment path (leave blank to finish): ",
                required=False
            )
            if not attachment:
                break
            if os.path.exists(attachment):
                attachments.append(attachment)
            else:
                print("File not found. Please try again.")
        
        use_template = EmailSystemCLI.get_input(
            "Use template? (y/n): ",
            required=False
        ).lower() == 'y'
        
        template_name = None
        template_context = None
        if use_template:
            template_name = EmailSystemCLI.get_input("Template name: ")
            # In a real implementation, you'd collect template context variables
        
        success = email_sender.send_email(
            subject=subject,
            body=body,
            recipient=[r.strip() for r in recipient.split(',')],
            sender=sender or None,
            attachments=attachments,
            template_name=template_name if use_template else None,
            template_context=template_context
        )
        
        if success:
            print("Email sent successfully!")
        else:
            print("Failed to send email. Check logs for details.")
    
    @staticmethod
    def _schedule_email(email_sender: SecureEmailSender) -> None:
        """Handle email scheduling"""
        print("\nSchedule Email\n" + "-"*20)
        
        # Get all the same details as send_email_now
        sender = EmailSystemCLI.get_input(
            "Sender email [leave blank for default]: ",
            required=False,
            validator=EmailValidator.is_valid_email
        )
        
        recipient = EmailSystemCLI.get_input(
            "Recipient email(s), comma-separated: ",
            validator=lambda x: all(EmailValidator.is_valid_email(e.strip()) for e in x.split(','))
        )
        
        subject = EmailSystemCLI.get_input("Subject: ")
        body = EmailSystemCLI.get_input("Body: ")
        
        schedule_time = EmailSystemCLI.get_input(
            "Schedule time (HH:MM, 24-hour format): ",
            validator=lambda x: re.match(r'^([0-1]?[0-9]|2[0-3]):[0-5][0-9]$', x)
        )
        
        attachments = []
        while True:
            attachment = EmailSystemCLI.get_input(
                "Attachment path (leave blank to finish): ",
                required=False
            )
            if not attachment:
                break
            if os.path.exists(attachment):
                attachments.append(attachment)
            else:
                print("File not found. Please try again.")
        
        email_sender.schedule_email(
            subject=subject,
            body=body,
            recipient=[r.strip() for r in recipient.split(',')],
            schedule_time=schedule_time,
            sender=sender or None,
            attachments=attachments
        )
        
        print(f"Email scheduled to be sent at {schedule_time}")


if __name__ == "__main__":
    try:
        # Check if we should run in CLI mode
        if len(sys.argv) > 1 and sys.argv[1] == '--cli':
            EmailSystemCLI.run()
        else:
            # Alternatively, could run as a service
            config_manager = ConfigManager()
            email_sender = SecureEmailSender(config_manager)
            email_sender.run_scheduled_emails()
    except Exception as e:
        logger.error(f"System error: {e}")
        sys.exit(1)
