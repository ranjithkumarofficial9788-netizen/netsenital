import os

from app import create_app


required_variables = ("DATABASE_URL", "SECRET_KEY")
missing_variables = [name for name in required_variables if not os.getenv(name)]
if missing_variables:
    raise RuntimeError(
        "Missing required production environment variables: "
        + ", ".join(missing_variables)
    )

app = create_app("production")
