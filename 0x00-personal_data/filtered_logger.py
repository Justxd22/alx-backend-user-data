#!/usr/bin/env python3
"""Dataa obfuscator."""


import re
import os
import logging
from typing import List
import mysql.connector

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str,
                 ) -> str:
    """Dataa obfuscator."""
    p = f"({'|'.join(fields)})=[^{separator}]*"
    return re.sub(p, lambda x: f'{x.group(1)}={redaction}', message)


class RedactingFormatter(logging.Formatter):
    """Redacting Formatter class."""

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        """Init class."""
        self.fields = fields
        super(RedactingFormatter, self).__init__(self.FORMAT)

    def format(self, record: logging.LogRecord) -> str:
        """Format records."""
        msg = super(RedactingFormatter, self).format(record)
        return filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Logger for user data."""
    logger = logging.getLogger("user_data")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(PII_FIELDS))
    logger.setLevel(logging.INFO)
    logger.propagate = False
    logger.addHandler(stream_handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """Connect to db securly."""
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    c = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return c


def main():
    """User data records in a table."""
    f = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = f.split(',')
    query = "SELECT {} FROM users;".format(f)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


if __name__ == '__main__':
    main()
