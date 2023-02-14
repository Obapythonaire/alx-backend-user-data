#!/usr/bin/env python3
"""DB module
"""
from sqlalchemy import create_engine, tuple_
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.orm.exc import NoResultFound
from sqlalchemy.exc import InvalidRequestError


from user import Base, User


class DB:
    """DB class
    """

    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine("sqlite:///a.db", echo=True)
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """Adds a user to the database
        """
        try:
            user = User(email=email, hashed_password=hashed_password)
            self._session.add(user)
            self._session.commit()
        except Exception:
            self._session.rollback()
            user_1 = None
        return user

    def find_user_by(self, **kwargs) -> User:
        """Finds user based on provided kwargs
        """
        keys = []
        values = []
        for key, value in kwargs.items():
            if hasattr(User, key):
                keys.append(getattr(User, key))
                values.append(value)
            else:
                raise InvalidRequestError()
        res = self._session.query(User).filter(tuple_(
            *keys).in_([tuple(values)])).first()
        if res is None:
            raise NoResultFound()
        return res

    def update_user(self, user_id: int, **kwargs) -> None:
        """Updates an existing user
        """
        user = self.find_user_by(id=user_id)
        if user is None:
            return
        update_info = {}
        for key, value in kwargs.items():
            if hasattr(User, key):
                update_info[getattr(User, key)] = value
            else:
                raise ValueError()
            self._session.query(User).filter(User.id == user_id).update(
                    update_info, synchronize_session=False,)
            self._session.commit()
