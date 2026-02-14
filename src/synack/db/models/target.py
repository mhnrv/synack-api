"""db/models/target.py

Database Model for the Target item
"""

import sqlalchemy as sa
from sqlalchemy.orm import declarative_base
from .category import Category
from .organization import Organization

Base = declarative_base()


class Target(Base):
    __tablename__ = 'targets'
    slug = sa.Column(sa.VARCHAR(20), primary_key=True)
    category = sa.Column(sa.INTEGER)
    organization = sa.Column(sa.VARCHAR(20))
    codename = sa.Column(sa.VARCHAR(100))
    activated_at = sa.Column(sa.INTEGER)
    name = sa.Column(sa.VARCHAR(100))
    collaboration_criteria = sa.Column(sa.VARCHAR(100))
    vulnerability_discovery = sa.Column(sa.BOOLEAN, default=False)
    is_registered = sa.Column(sa.BOOLEAN, default=False)
