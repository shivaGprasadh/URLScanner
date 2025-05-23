
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Pattern(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    category = db.Column(db.String(50), nullable=False)
    pattern = db.Column(db.Text, nullable=False)
