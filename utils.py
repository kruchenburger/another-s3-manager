"""
Utility functions for validation and sanitization
"""
import re
from typing import Optional, Union


def sanitize_path(path: str) -> str:
    """
    Sanitize S3 path to prevent path traversal attacks.

    Args:
        path: S3 path to sanitize

    Returns:
        Sanitized path

    Raises:
        ValueError: If path contains invalid characters
    """
    if not path:
        return ""

    # Remove leading/trailing slashes and normalize
    path = path.strip().strip('/')

    # Check for path traversal attempts
    if '..' in path or path.startswith('/'):
        raise ValueError("Invalid path: path traversal not allowed")

    # Check for invalid characters (basic validation)
    if re.search(r'[<>:"|?*\x00-\x1f]', path):
        raise ValueError("Invalid path: contains invalid characters")

    return path


def sanitize_bucket_name(bucket_name: str) -> str:
    """
    Sanitize S3 bucket name.

    Args:
        bucket_name: Bucket name to sanitize

    Returns:
        Sanitized bucket name

    Raises:
        ValueError: If bucket name is invalid
    """
    if not bucket_name:
        raise ValueError("Bucket name cannot be empty")

    bucket_name = bucket_name.strip()

    # Basic S3 bucket name validation
    if len(bucket_name) < 3 or len(bucket_name) > 63:
        raise ValueError("Bucket name must be between 3 and 63 characters")

    # Check for invalid characters (S3 bucket names can contain lowercase letters, numbers, dots, and hyphens)
    # Must start and end with letter or number
    if not re.match(r'^[a-z0-9][a-z0-9\-\.]*[a-z0-9]$|^[a-z0-9]$', bucket_name.lower()):
        raise ValueError("Invalid bucket name format")

    return bucket_name.lower()


def validate_role_name(role_name: Optional[str]) -> Optional[str]:
    """
    Validate role name.

    Args:
        role_name: Role name to validate

    Returns:
        Validated role name or None
    """
    if not role_name:
        return None

    role_name = role_name.strip()
    if not role_name:
        return None

    # Basic validation - no special characters
    if re.search(r'[<>:"|?*\x00-\x1f]', role_name):
        raise ValueError("Invalid role name: contains invalid characters")

    return role_name


def format_boto_error(error: Union[Exception, BaseException]) -> str:
    """
    Extract user-friendly error message from botocore/boto3 exceptions.

    Args:
        error: Exception from botocore/boto3

    Returns:
        User-friendly error message
    """
    # Handle specific botocore exceptions
    error_type = type(error).__name__
    error_message = str(error)

    # Check for SSO token errors - this is the most common case
    if "UnauthorizedSSOTokenError" in error_type:
        return "AWS SSO session has expired or is invalid. Please run 'aws sso login' with the corresponding profile to refresh your session."

    # Check for SSO-related messages in the error text
    if "SSO" in error_message and ("expired" in error_message.lower() or "invalid" in error_message.lower()):
        # Try to extract profile name if mentioned
        if "profile" in error_message.lower():
            return "AWS SSO session has expired or is invalid. Please run 'aws sso login' with the corresponding profile to refresh your session."
        return "AWS SSO session has expired or is invalid. Please run 'aws sso login' to refresh your session."

    # Check for generic expired credentials that require re-authentication
    lower_message = error_message.lower()
    expired_phrases = [
        "token is expired",
        "token expired",
        "expiredtoken",
        "basic claim validations",
        "credentials have expired",
        "session expired",
    ]
    if any(phrase in lower_message for phrase in expired_phrases):
        return (
            "AWS credentials have expired and automatic refresh failed. "
            "Please re-authenticate the container or refresh the service account token."
        )

    # Check for credential errors
    if "InvalidAccessKeyId" in error_message or "InvalidAccessKeyId" in error_type:
        return "Invalid AWS Access Key ID. Please check your credentials."

    if "SignatureDoesNotMatch" in error_message or "SignatureDoesNotMatch" in error_type:
        return "AWS credentials signature mismatch. Please check your secret access key."

    if "NoCredentialsError" in error_type or "Unable to locate credentials" in error_message:
        return "AWS credentials not found. Please configure your credentials."

    # Handle ClientError with error codes
    if hasattr(error, 'response'):
        error_code = error.response.get('Error', {}).get('Code', '')
        error_msg = error.response.get('Error', {}).get('Message', '')
        operation_name = error.response.get('ResponseMetadata', {}).get('RequestId', '')

        if error_code == 'AccessDenied':
            # Check if this is an assume role error
            if 'assume' in error_message.lower() or 'AssumeRole' in error_type:
                return (
                    f"Access denied when trying to assume IAM role. "
                    f"Check that the pod/service account has sts:AssumeRole permission for the target role. "
                    f"Error: {error_msg}" if error_msg else "Access denied. Check IAM permissions for role assumption."
                )
            return f"Access denied: {error_msg}" if error_msg else "Access denied. Check your IAM permissions."

        if error_code == 'NoSuchBucket':
            return f"Bucket not found: {error_msg}" if error_msg else "Bucket not found."

        if error_code == 'NoSuchKey':
            return f"Object not found: {error_msg}" if error_msg else "Object not found."

        if error_code == 'InvalidAccessKeyId':
            return "Invalid AWS Access Key ID. Please check your credentials."

        if error_code == 'SignatureDoesNotMatch':
            return "AWS credentials signature mismatch. Please check your secret access key."

        # Return the error message from AWS if available
        if error_msg:
            return error_msg

    # For other exceptions, try to extract meaningful message
    # Remove common prefixes that don't add value
    message = error_message
    prefixes_to_remove = [
        "An error occurred (",
        ") when calling the ",
        " operation: ",
    ]

    # Try to extract just the error description
    if "operation:" in message:
        parts = message.split("operation:")
        if len(parts) > 1:
            message = parts[-1].strip()

    # Clean up the message
    message = message.strip()
    if message.startswith("An error occurred"):
        # Try to extract the actual error message
        if ":" in message:
            message = message.split(":", 1)[-1].strip()

    return message if message else "An error occurred while accessing AWS services."


def format_content_disposition(filename: str) -> str:
    """
    Format Content-Disposition header with UTF-8 support (RFC 5987).

    Args:
        filename: Filename that may contain non-ASCII characters

    Returns:
        Properly formatted Content-Disposition header value
    """
    # Create ASCII-safe fallback filename (replace non-ASCII with underscore)
    ascii_filename = filename.encode('ascii', 'replace').decode('ascii').replace('?', '_')

    # URL-encode the UTF-8 filename for RFC 5987 format
    # Encode filename to UTF-8 bytes, then percent-encode each byte
    utf8_bytes = filename.encode('utf-8')
    # Convert bytes to percent-encoded string (each byte becomes %XX)
    utf8_filename = ''.join(f'%{b:02X}' for b in utf8_bytes)

    # Use RFC 5987 format: filename="fallback"; filename*=UTF-8''encoded
    return f'attachment; filename="{ascii_filename}"; filename*=UTF-8\'\'{utf8_filename}'
