"""Validator Module"""
import re
from flask_babel import Babel, gettext as _

def perform_validation(input_data, pattern):
    """Utility to perform regex matching."""
    return re.match(pattern, input_data) is not None

def check_password(pwd: str):
    """Checks the validity of a password."""
    pattern = r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$"
    return perform_validation(pwd, pattern)

def check_email(addr: str):
    """Checks the validity of an email address."""
    pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    return perform_validation(addr, pattern)

def validate_user_details(**kwargs):
    """Validates user details including name, email, and password."""
    required_fields = ['email', 'password', 'name']
    errors = ', '.join(f'{field.capitalize()} is required' for field in required_fields if not kwargs.get(field))
    if errors:
        return errors

    if any(not isinstance(kwargs[field], str) for field in required_fields):
        return ', '.join(f'{field.capitalize()} must be a string' for field in required_fields)

    if not check_email(kwargs['email']):
        return _('Invalid email format')

    if not check_password(kwargs['password']):
        return _('Password is invalid.')

    if not 2 <= len(kwargs['name']) <= 30:
        return _('Name must be between 2 and 30 words')

    return True

def validate_credentials(email, password):
    """Simplifies validation for just email and password."""
    if not (email and password):
        return _('Email and Password is required')

    if not check_email(email):
        return _('Email format is incorrect')

    if not check_password(password):
        return _('Password does not meet the required standards')

    return True
