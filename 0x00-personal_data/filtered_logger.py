#!/usr/bin/env python3
""" Defines filter_datum """
import logging
import re
from typing import List
from os import environ
import mysql.connector as mc


PII_FIELDS = ("name", "phone", "email", "ssn", "password")


def filter_datum(
        fields: List[str],
        redaction: str, message: str, separator: str) -> str:
    """ Returns an obfuscated log message """
    for key in fields:
        message = re.sub(f'{key}=.*?{separator}',
                         f'{key}={redaction}{separator}', message)
    return message


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Filters in incoming records """
        return filter_datum(self.fields, self.REDACTION,
                            super(RedactingFormatter, self).format(record),
                            self.SEPARATOR)


def get_logger() -> logging.Logger:
    """Returns a log object"""
    log = logging.getLogger("user_data")
    log.setLevel(logging.INFO)
    log.propagate = False
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(RedactingFormatter(List(PII_FIELDS)))
    log.addHandler(stream_handler)
    return log


def get_db() -> mc.connection.MySQLConnection:
    """Returns a MySQL Connector"""
    uname = environ.get("PERSONAL_DATA_DB_USERNAME", "root")
    pwd = environ.get("PERSONAL_DATA_DB_PASSWORD", "")
    h = environ.get("PERSONAL_DATA_DB_HOST", "localhost")
    db = environ.get("PERSONAL_DATA_DB_NAME")
    return mc.connection.MySQLConnection(user=uname, password=pwd,
                                         host=h, database=db)


def main():
    """ Obtains a database connection using get_db and retrieves all rows
    in the users table then display each row under a filtered format """
    db = get_db()
    cur_db = db.cursor()
    cur_db.execute("SELECT * FROM users;")
    field_names = [i[0] for i in cur_db.description]
    log = get_logger()
    for r in cur_db:
        str_r = "".join(f"{f}={str(l)}; " for l, f in zip(r, field_names))
        log.info(str_r.strip())
    cur_db.close()
    db.close()


if __name__ == "__main__":
    main()
