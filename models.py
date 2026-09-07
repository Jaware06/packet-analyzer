from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin
from datetime import datetime
import json

db = SQLAlchemy()


class User(db.Model, UserMixin):
    __tablename__ = 'users'

    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(
        db.String(80),
        unique=True,
        nullable=False
    )

    email = db.Column(
        db.String(120),
        unique=True,
        nullable=False
    )

    password_hash = db.Column(
        db.String(256),
        nullable=False
    )

    email_verified = db.Column(
        db.Boolean,
        default=False
    )

    # Password reset fields
    reset_token = db.Column(
        db.String(128),
        unique=True,
        nullable=True
    )

    reset_token_expiry = db.Column(
        db.DateTime,
        nullable=True
    )

    analyses = db.relationship(
        'Analysis',
        backref='user',
        lazy=True,
        cascade="all, delete-orphan"
    )

    def __repr__(self):
        return f"<User {self.username}>"


class Analysis(db.Model):
    __tablename__ = 'analyses'

    id = db.Column(
        db.Integer,
        primary_key=True
    )

    user_id = db.Column(
        db.Integer,
        db.ForeignKey('users.id'),
        nullable=False
    )

    filename = db.Column(
        db.String(255),
        nullable=False
    )

    timestamp = db.Column(
        db.DateTime,
        default=datetime.utcnow
    )

    total_packets = db.Column(
        db.Integer,
        default=0
    )

    threat_count = db.Column(
        db.Integer,
        default=0
    )

    unique_ips = db.Column(
        db.Integer,
        default=0
    )

    protocol_counts_json = db.Column(
        db.Text,
        default='{}'
    )

    threats_json = db.Column(
        db.Text,
        default='[]'
    )

    packets_json = db.Column(
        db.Text,
        default='[]'
    )

    devices_json = db.Column(
        db.Text,
        default='[]'
    )

    @property
    def protocol_counts(self):
        try:
            return json.loads(
                self.protocol_counts_json
            ) if self.protocol_counts_json else {}
        except Exception:
            return {}

    @protocol_counts.setter
    def protocol_counts(self, value):
        self.protocol_counts_json = json.dumps(
            value or {}
        )

    @property
    def threats(self):
        try:
            return json.loads(
                self.threats_json
            ) if self.threats_json else []
        except Exception:
            return []

    @threats.setter
    def threats(self, value):
        self.threats_json = json.dumps(
            value or []
        )

    @property
    def packets(self):
        try:
            return json.loads(
                self.packets_json
            ) if self.packets_json else []
        except Exception:
            return []

    @packets.setter
    def packets(self, value):
        self.packets_json = json.dumps(
            value or []
        )

    @property
    def devices(self):
        try:
            return json.loads(
                self.devices_json
            ) if self.devices_json else []
        except Exception:
            return []

    @devices.setter
    def devices(self, value):
        self.devices_json = json.dumps(
            value or []
        )

    def to_dict(self):

        return {
            'id': self.id,
            'filename': self.filename,
            'timestamp':
                self.timestamp.strftime(
                    '%Y-%m-%d %H:%M:%S'
                ) if self.timestamp else None,
            'total_packets': self.total_packets,
            'threat_count': self.threat_count,
            'unique_ips': self.unique_ips,
            'protocol_counts':
                self.protocol_counts,
            'threats':
                self.threats,
            'packets':
                self.packets,
            'devices':
                self.devices
        }

    def __repr__(self):
        return (
            f"<Analysis {self.filename} "
            f"user_id={self.user_id}>"
        )