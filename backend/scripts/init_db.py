from db.database import engine, Base
import db.models # Import models to ensure they are registered with Base

def init_db():
    print("Initializing database...")
    Base.metadata.create_all(bind=engine)
    print("Database initialized successfully.")

if __name__ == "__main__":
    init_db()
