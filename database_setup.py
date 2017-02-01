import sys
from sqlalchemy import Column, ForeignKey, Integer, String
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import relationship
from sqlalchemy import create_engine

Base = declarative_base()


class User(Base):
	__tablename__ = 'user'

	id = Column(Integer, primary_key=True)
	name = Column(String(100), nullable=False)
	email = Column(String(200), nullable=False)
	picture = Column(String(250))


class Category(Base):
	__tablename__ = 'category'

	id = Column(Integer, primary_key=True)
	name = Column(String(250), nullable=False)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialise(self):
		return {
			'id' : self.id,
			'name' : self.name
		}


class NGO(Base):
	__tablename__ = 'ngo'

	id = Column(Integer, primary_key=True)
	name = Column(String(80), nullable=False)
	focus = Column(String(250))
	founded = Column(String(80))
	website = Column(String(250))
	continent = Column(String(80), nullable=False)
	category_id = Column(Integer, ForeignKey('restaurant.id'))
	category = relationship(Restaurant)
	user_id = Column(Integer, ForeignKey('user.id'))
	user = relationship(User)

	@property
	def serialise(self):
		return {
			'id' : self.id,
			'name' : self.name,
			'focus' : self.focus,
			'founded' : self.founded,
			'website' : self.website,
			'continent' : self.continent,
			'category' : self.category.name
		}


engine = create_engine('sqlite:///ngosandusers.db')
Base.metadata.create_all(engine)
