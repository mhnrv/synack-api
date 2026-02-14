"""db/model/url.py

Database Model for the Url item
"""

import sqlalchemy as sa
from sqlalchemy.orm import declarative_base
from .ip import IP

Base = declarative_base()


class Url(Base):
    __tablename__ = 'urls'
    id = sa.Column(sa.Integer, autoincrement=True, primary_key=True)
    ip = sa.Column(sa.Integer)
    url = sa.Column(sa.VARCHAR(1024), default="")
    screenshot_url = sa.Column(sa.VARCHAR(1024), default="")
