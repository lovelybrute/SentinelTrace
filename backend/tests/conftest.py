import os
import sys
import pytest
from fastapi.testclient import TestClient

# Add backend directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from main import app
from database import init_db

@pytest.fixture(scope="session", autouse=True)
def setup_database():
    init_db()

@pytest.fixture
def client():
    return TestClient(app)

@pytest.fixture
def sample_emails_dir():
    return os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "samples"))
