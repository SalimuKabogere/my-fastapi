"""Database initialization module."""

from backend.models.database import Base, engine
from backend.models.user import *  # Import all models
import logging

logger = logging.getLogger(__name__)

def init_database():
    """Initialize database tables."""
    try:
        logger.info("Creating database tables...")
        Base.metadata.create_all(bind=engine)
        logger.info("Database tables created successfully")
        return True
    except Exception as e:
        logger.error(f"Error creating database tables: {e}")
        return False
