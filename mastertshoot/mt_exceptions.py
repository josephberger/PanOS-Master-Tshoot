# mastertshoot/mt_exceptions.py

"""
Custom exception classes for the Master Troubleshooter application.
Provides a centralized and hierarchical structure for error handling.
"""

class MTBaseException(Exception):
    """Base exception for all custom Master Troubleshooter exceptions."""
    pass

class MTControllerException(MTBaseException):
    """Base exception for errors originating from the MTController layer or its services."""
    pass

class MTDatabaseSchemaError(MTControllerException):
    """Exception raised when the database schema is not found or is incomplete."""
    pass

# Exceptions for specific service layers, inheriting from MTControllerException
# This allows granular catching while still enabling broader MTControllerException catches.

class MTBuilderException(MTControllerException):
    """Exception raised for errors specific to the MTBuilder operations."""
    pass

class MTDatabaseManagerException(MTControllerException):
    """Exception raised for errors specific to the MTDatabaseManager operations."""
    pass

class MTAPIServiceException(MTControllerException):
    """Exception raised for errors specific to the MTAPIService operations (general API errors)."""
    pass

# More specific API-related exceptions, inheriting from MTAPIServiceException
class MTpanoramaException(MTAPIServiceException):
    """Exception raised for errors specific to Panorama API interactions."""
    pass

class MTngfwException(MTAPIServiceException):
    """Exception raised for errors specific to NGFW API interactions."""
    pass