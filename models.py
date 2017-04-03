from sqlalchemy import Column, ForeignKey, Integer, String, DateTime
from sqlalchemy.ext.declarative import declarative_base, declared_attr
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime
import config

Base = declarative_base()
config = config.DevConfiguration()
engine = create_engine(config.SQLALCHEMY_DATABASE_URI)


class ScannerModelMixin(object):

    @declared_attr
    def __tablename__(cls):
        return cls.__name__.lower()

    id = Column(Integer, primary_key=True)
    created_at = Column(DateTime, default=datetime.datetime.now())


class Directory(ScannerModelMixin, Base):
    directory_path = Column(String(4096), nullable=False, unique=True)


class Filename(ScannerModelMixin, Base):
    filename = Column(String(255), index=True, nullable=False)
    mime_type = Column(String, index=True)
    hash = Column(String(56), nullable=False, index=True, unique=True)
    directory_id = Column(Integer, ForeignKey('directory.id'))
    directory = relationship(Directory)


class Scan(ScannerModelMixin, Base):
    ended_at = Column(DateTime, default=datetime.datetime.now())
    added = Column(Integer)
    existed = Column(Integer)
    total = Column(Integer)
    started_epoch = Column(Integer)
    ended_epoch = Column(Integer)
    path = Column(String)
    type = Column(String(4))


engine = create_engine(config.SQLALCHEMY_DATABASE_URI)

Base.metadata.create_all(engine)
