from sqlmodel import SQLModel, create_engine, Session
from . import setting

connection_string: str = str(setting.DATABASE_URL).replace("postgresql", "postgresql+psycopg")
engine = create_engine(connection_string, connect_args={}, pool_recycle=300, pool_size=10)
def create_tables():
    SQLModel.metadata.create_all(engine) #SQLMOdel is inherited from SQLAlchemy


def get_session():
    with Session(engine) as session:
        yield session