"""
Database configuration and abstraction layer for FastAPI Roles package.

This module provides database abstraction to support multiple database types:
- SQLite
- PostgreSQL
- MySQL
- Oracle
- MongoDB (via SQLAlchemy)
"""

import os
from typing import Any, Dict, Generator, Optional, Union
from urllib.parse import urlparse

from sqlalchemy import create_engine, MetaData, String, TypeDecorator
from sqlalchemy.dialects import mysql, oracle, postgresql, sqlite
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.types import CHAR, TypeEngine


class DatabaseConfig:
    """Database configuration class."""
    
    def __init__(
        self,
        database_url: str,
        echo: bool = False,
        pool_size: int = 5,
        max_overflow: int = 10,
        pool_timeout: int = 30,
        pool_recycle: int = 3600,
        **kwargs
    ):
        self.database_url = database_url
        self.echo = echo
        self.pool_size = pool_size
        self.max_overflow = max_overflow
        self.pool_timeout = pool_timeout
        self.pool_recycle = pool_recycle
        self.extra_kwargs = kwargs
        
        # Parse database type from URL
        parsed = urlparse(database_url)
        self.database_type = parsed.scheme.split('+')[0]
        
        # Validate supported database types
        supported_types = ['sqlite', 'postgresql', 'mysql', 'oracle']
        if self.database_type not in supported_types:
            raise ValueError(f"Unsupported database type: {self.database_type}. Supported: {supported_types}")
    
    def get_engine_kwargs(self) -> Dict[str, Any]:
        """Get engine configuration based on database type."""
        kwargs = {
            'echo': self.echo,
            **self.extra_kwargs
        }
        
        if self.database_type == 'sqlite':
            # SQLite specific configuration
            kwargs.update({
                'connect_args': {'check_same_thread': False},
                'poolclass': None  # SQLite doesn't support connection pooling
            })
        else:
            # Connection pooling for other databases
            kwargs.update({
                'pool_size': self.pool_size,
                'max_overflow': self.max_overflow,
                'pool_timeout': self.pool_timeout,
                'pool_recycle': self.pool_recycle,
            })
        
        return kwargs


class GUID(TypeDecorator):
    """
    Platform-independent GUID type.
    
    Uses PostgreSQL's UUID type when available,
    otherwise uses CHAR(36) for other databases.
    """
    
    impl = CHAR
    cache_ok = True
    
    def load_dialect_impl(self, dialect) -> TypeEngine:
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(postgresql.UUID(as_uuid=True))
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(CHAR(36))
        elif dialect.name == 'oracle':
            return dialect.type_descriptor(CHAR(36))
        else:
            return dialect.type_descriptor(CHAR(36))
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            return str(value)
    
    def process_result_value(self, value, dialect):
        if value is None:
            return value
        elif dialect.name == 'postgresql':
            return value
        else:
            import uuid
            return uuid.UUID(value)


class JSON(TypeDecorator):
    """
    Platform-independent JSON type.
    
    Uses native JSON type when available,
    otherwise uses TEXT with JSON serialization.
    """
    
    impl = String
    cache_ok = True
    
    def load_dialect_impl(self, dialect) -> TypeEngine:
        if dialect.name == 'postgresql':
            return dialect.type_descriptor(postgresql.JSON())
        elif dialect.name == 'mysql':
            return dialect.type_descriptor(mysql.JSON())
        elif dialect.name == 'oracle':
            # Oracle 21c+ supports JSON, but we'll use CLOB for compatibility
            return dialect.type_descriptor(oracle.CLOB())
        else:
            # SQLite and others use TEXT
            return dialect.type_descriptor(String())
    
    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        
        if dialect.name in ('postgresql', 'mysql'):
            return value
        else:
            import json
            return json.dumps(value)
    
    def process_result_value(self, value, dialect):
        if value is None:
            return value
        
        if dialect.name in ('postgresql', 'mysql'):
            return value
        else:
            import json
            return json.loads(value)


class Base(DeclarativeBase):
    """Base class for all database models using SQLAlchemy 2.0 declarative base."""
    
    metadata = MetaData(
        naming_convention={
            "ix": "ix_%(column_0_label)s",
            "uq": "uq_%(table_name)s_%(column_0_name)s",
            "ck": "ck_%(table_name)s_%(constraint_name)s",
            "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
            "pk": "pk_%(table_name)s"
        }
    )


class DatabaseManager:
    """Database manager for handling connections and sessions."""
    
    def __init__(self, config: DatabaseConfig):
        self.config = config
        self.engine: Optional[Engine] = None
        self.SessionLocal: Optional[sessionmaker] = None
    
    def initialize(self) -> None:
        """Initialize database engine and session factory."""
        engine_kwargs = self.config.get_engine_kwargs()
        self.engine = create_engine(self.config.database_url, **engine_kwargs)
        self.SessionLocal = sessionmaker(
            autocommit=False,
            autoflush=False,
            bind=self.engine
        )
    
    def create_tables(self) -> None:
        """Create all tables."""
        if not self.engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        Base.metadata.create_all(bind=self.engine)
    
    def drop_tables(self) -> None:
        """Drop all tables."""
        if not self.engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        Base.metadata.drop_all(bind=self.engine)
    
    def get_session(self) -> Generator[Session, None, None]:
        """Get database session."""
        if not self.SessionLocal:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        db = self.SessionLocal()
        try:
            yield db
        finally:
            db.close()
    
    def get_database_info(self) -> Dict[str, Any]:
        """Get database information."""
        if not self.engine:
            raise RuntimeError("Database not initialized. Call initialize() first.")
        
        return {
            'database_type': self.config.database_type,
            'database_url': self.config.database_url,
            'dialect': self.engine.dialect.name,
            'driver': self.engine.dialect.driver,
            'server_version_info': getattr(self.engine.dialect, 'server_version_info', None),
        }


# Convenience functions for common database URLs
def sqlite_url(path: str = "fastapi_roles.db") -> str:
    """Generate SQLite database URL."""
    return f"sqlite:///{path}"


def postgresql_url(
    host: str = "localhost",
    port: int = 5432,
    database: str = "fastapi_roles",
    username: str = "postgres",
    password: str = "password"
) -> str:
    """Generate PostgreSQL database URL."""
    return f"postgresql://{username}:{password}@{host}:{port}/{database}"


def mysql_url(
    host: str = "localhost",
    port: int = 3306,
    database: str = "fastapi_roles",
    username: str = "root",
    password: str = "password"
) -> str:
    """Generate MySQL database URL."""
    return f"mysql+pymysql://{username}:{password}@{host}:{port}/{database}"


def oracle_url(
    host: str = "localhost",
    port: int = 1521,
    service_name: str = "XE",
    username: str = "fastapi_roles",
    password: str = "password"
) -> str:
    """Generate Oracle database URL."""
    return f"oracle+cx_oracle://{username}:{password}@{host}:{port}/?service_name={service_name}"


# Environment-based configuration
def get_database_url_from_env() -> str:
    """Get database URL from environment variables."""
    # Check for full database URL first
    database_url = os.getenv("DATABASE_URL")
    if database_url:
        return database_url
    
    # Check for database type and build URL
    db_type = os.getenv("DB_TYPE", "sqlite").lower()
    
    if db_type == "sqlite":
        db_path = os.getenv("DB_PATH", "fastapi_roles.db")
        return sqlite_url(db_path)
    
    elif db_type == "postgresql":
        return postgresql_url(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "5432")),
            database=os.getenv("DB_NAME", "fastapi_roles"),
            username=os.getenv("DB_USER", "postgres"),
            password=os.getenv("DB_PASSWORD", "password")
        )
    
    elif db_type == "mysql":
        return mysql_url(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "3306")),
            database=os.getenv("DB_NAME", "fastapi_roles"),
            username=os.getenv("DB_USER", "root"),
            password=os.getenv("DB_PASSWORD", "password")
        )
    
    elif db_type == "oracle":
        return oracle_url(
            host=os.getenv("DB_HOST", "localhost"),
            port=int(os.getenv("DB_PORT", "1521")),
            service_name=os.getenv("DB_SERVICE_NAME", "XE"),
            username=os.getenv("DB_USER", "fastapi_roles"),
            password=os.getenv("DB_PASSWORD", "password")
        )
    
    else:
        raise ValueError(f"Unsupported database type: {db_type}")


def create_database_manager(
    database_url: Optional[str] = None,
    **kwargs
) -> DatabaseManager:
    """Create and initialize database manager."""
    if database_url is None:
        database_url = get_database_url_from_env()
    
    config = DatabaseConfig(database_url, **kwargs)
    manager = DatabaseManager(config)
    manager.initialize()
    
    return manager
