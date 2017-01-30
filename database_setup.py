from sqlalchemy import Column, ForeignKey, Integer, String, Boolean, DateTime
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine
import datetime
from sqlalchemy.dialects.mysql import DATETIME
 
# New imports for this step
from flask import session as login_session
import random
import string 

Base = declarative_base()

class User(Base):
    __tablename__ = 'user'

    id = Column(Integer, primary_key=True)
    name = Column(String(250), nullable=False)
    email = Column(String(250), nullable=False)
    picture = Column(String(250))

class Category(Base):
    __tablename__ = 'category'
   
    id = Column(Integer, primary_key=True)
    name = Column(String(100), nullable=False)
    description = Column(String(250))
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User) 

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'name'         : self.name,
           'id'           : self.id,
           'description'  : self.description,
           'user_id'      : self.user_id
       }

class Topic(Base):
    __tablename__ = 'topic'

    id = Column(Integer, primary_key = True)
    title =Column(String(80), nullable = False)
    content = Column(String(5000), nullable = False)
    summary = Column(String(10000))
    created_at = Column(DateTime, default=datetime.datetime.utcnow)
    category_id = Column(Integer,ForeignKey('category.id'))
    category = relationship(Category)
    user_id = Column(Integer, ForeignKey('user.id'))
    user = relationship(User)

    @property
    def serialize(self):
       """Return object data in easily serializeable format"""
       return {
           'title'          : self.title,
           'id'             : self.id,
           'content'        : self.content,
           'summary'        : self.summary,
           'created_at'     : self.created_at,
           'user_id'        : self.user_id,
           'category_id'    : self.category_id
       }

engine = create_engine('mysql://root:admin@localhost:3306/marriedtochinese1')
Base.metadata.create_all(engine)