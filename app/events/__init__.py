from flask import Blueprint

events_bp = Blueprint("events", __name__)

from app.events import routes
