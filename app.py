from flask import Flask, request, jsonify, render_template, redirect, url_for
from flask_cors import CORS
from flask_login import LoginManager, login_required, current_user
from scapy.all import rdpcap, IP, TCP, UDP, ICMP, ARP

import os
import secrets
from collections import Counter

from models import db, User, Analysis
from auth import auth_bp
from detector import ThreatDetector
from sniffer import LiveSniffer


# ============================================================
# CREATE FLASK APP FIRST
# ============================================================

app = Flask(
    __name__,
    template_folder="templates",
    static_folder="static"
)

CORS(app)


# ============================================================
# CONFIGURATION
# ============================================================

app.config["SECRET_KEY"] = os.environ.get(
    "SECRET_KEY",
    secrets.token_hex(32)
)

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///database.db"

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False


# ============================================================
# UPLOAD CONFIGURATION
# ============================================================

UPLOAD_FOLDER = "uploads"

os.makedirs(
    UPLOAD_FOLDER,
    exist_ok=True
)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

ALLOWED_EXTENSIONS = {
    "pcap",
    "pcapng"
}


# ============================================================
# DATABASE
# ============================================================

db.init_app(app)


# ============================================================
# LOGIN MANAGER
# ============================================================

login_manager = LoginManager()

login_manager.login_view = "auth.login"

login_manager.init_app(app)


@login_manager.user_loader
def load_user(user_id):

    return User.query.get(int(user_id))


# ============================================================
# CREATE DATABASE TABLES
# ============================================================

with app.app_context():

    db.create_all()


# ============================================================
# REGISTER AUTH BLUEPRINT
# ============================================================

app.register_blueprint(
    auth_bp,
    url_prefix="/auth"
)


# ============================================================
# LIVE SNIFFER
# ============================================================

live_sniffer = LiveSniffer()


# ============================================================
# FILE VALIDATION
# ============================================================

def allowed_file(filename):

    return (
        "." in filename
        and
        filename.rsplit(".", 1)[1].lower()
        in ALLOWED_EXTENSIONS
    )


# ============================================================
# HOME
# ============================================================

@app.route("/")
def index():

    if current_user.is_authenticated:

        return redirect(
            url_for("dashboard_view")
        )

    return redirect(
        url_for("auth.login")
    )


# ============================================================
# DASHBOARD
# ============================================================

@app.route("/dashboard")
@login_required
def dashboard_view():

    return render_template(
        "dashboard.html",
        username=current_user.username
    )


# ============================================================
# UPLOAD PCAP
# ============================================================

@app.route("/upload", methods=["POST"])
@login_required
def upload_file():

    if "file" not in request.files:

        return jsonify({
            "error": "No file part in request"
        }), 400

    file = request.files["file"]

    if file.filename == "":

        return jsonify({
            "error": "No file selected"
        }), 400

    if not allowed_file(file.filename):

        return jsonify({
            "error":
            "Unsupported file format. "
            "Only .pcap and .pcapng are allowed."
        }), 400

    filename = (
        secrets.token_hex(8)
        + "_"
        + file.filename
    )

    filepath = os.path.join(
        app.config["UPLOAD_FOLDER"],
        filename
    )

    file.save(filepath)

    try:

        scapy_packets = rdpcap(filepath)

        packet_data = []

        for idx, packet in enumerate(scapy_packets):

            info = {
                "id": idx + 1,
                "protocol": "Other",
                "info": "",
                "length": len(packet)
            }

            if IP in packet:

                info["src"] = packet[IP].src
                info["dst"] = packet[IP].dst

                if TCP in packet:

                    info["protocol"] = "TCP"

                    info["info"] = (
                        f"Port: "
                        f"{packet[TCP].sport}"
                        f"->"
                        f"{packet[TCP].dport}"
                    )

                elif UDP in packet:

                    info["protocol"] = "UDP"

                    info["info"] = (
                        f"Port: "
                        f"{packet[UDP].sport}"
                        f"->"
                        f"{packet[UDP].dport}"
                    )

                    if (
                        packet[UDP].sport == 53
                        or
                        packet[UDP].dport == 53
                    ):

                        try:

                            if packet.haslayer("DNSQR"):

                                qname = (
                                    packet["DNSQR"]
                                    .qname
                                    .decode(
                                        "utf-8",
                                        errors="ignore"
                                    )
                                )

                                info["info"] += (
                                    f" | Domain: {qname}"
                                    f" | DNS Query"
                                )

                        except Exception:

                            pass

                elif ICMP in packet:

                    info["protocol"] = "ICMP"

                    info["info"] = (
                        f"ICMP Type "
                        f"{packet[ICMP].type}"
                    )

            elif ARP in packet:

                info["protocol"] = "ARP"

                op = (
                    "who-has"
                    if packet[ARP].op == 1
                    else "is-at"
                )

                info["src"] = packet[ARP].psrc

                info["dst"] = packet[ARP].pdst

                info["info"] = (
                    f"ARP: {op} "
                    f"{packet[ARP].psrc} -> "
                    f"{packet[ARP].pdst} "
                    f"MAC: {packet[ARP].hwsrc}"
                )

            packet_data.append(info)


        # ====================================================
        # THREAT DETECTION
        # ====================================================

        detector = ThreatDetector()

        threats = detector.analyze(
            packet_data
        )


        # ====================================================
        # UNIQUE DEVICES
        # ====================================================

        devices = set()

        for packet in packet_data:

            if packet.get("src"):

                devices.add(
                    packet["src"]
                )

            if packet.get("dst"):

                devices.add(
                    packet["dst"]
                )


        # ====================================================
        # PROTOCOL COUNTS
        # ====================================================

        protocol_counter = Counter(
            packet.get(
                "protocol",
                "Other"
            )
            for packet in packet_data
        )


        # ====================================================
        # SAVE ANALYSIS
        # ====================================================

        analysis = Analysis(

            user_id=current_user.id,

            filename=file.filename,

            total_packets=len(packet_data),

            threat_count=len(threats),

            unique_ips=len(devices)
        )

        analysis.protocol_counts = dict(
            protocol_counter
        )

        analysis.threats = threats

        analysis.packets = packet_data[:100]

        analysis.devices = list(devices)

        db.session.add(analysis)

        db.session.commit()


        if os.path.exists(filepath):

            os.remove(filepath)


        return jsonify(
            analysis.to_dict()
        ), 200


    except Exception as e:

        if os.path.exists(filepath):

            os.remove(filepath)

        return jsonify({
            "error":
            f"Failed to process file: {str(e)}"
        }), 500


# ============================================================
# LIVE CAPTURE START
# ============================================================

@app.route("/live/start", methods=["POST"])
@login_required
def start_live_sniff():

    success = live_sniffer.start()

    return jsonify({

        "status":
        "started"
        if success or live_sniffer.is_active()
        else "failed",

        "is_mock":
        live_sniffer.is_mock
    })


# ============================================================
# LIVE CAPTURE STOP
# ============================================================

@app.route("/live/stop", methods=["POST"])
@login_required
def stop_live_sniff():

    was_active = (
        live_sniffer.is_active()
    )

    live_sniffer.stop()

    packets = (
        live_sniffer.get_packets()
    )

    if was_active and packets:

        detector = ThreatDetector()

        threats = detector.analyze(
            packets
        )

        devices = set()

        for packet in packets:

            if packet.get("src"):

                devices.add(
                    packet["src"]
                )

            if packet.get("dst"):

                devices.add(
                    packet["dst"]
                )

        protocol_counter = Counter(
            packet.get(
                "protocol",
                "Other"
            )
            for packet in packets
        )

        analysis = Analysis(

            user_id=current_user.id,

            filename="Live Capture Session",

            total_packets=len(packets),

            threat_count=len(threats),

            unique_ips=len(devices)
        )

        analysis.protocol_counts = dict(
            protocol_counter
        )

        analysis.threats = threats

        analysis.packets = packets[:100]

        analysis.devices = list(devices)

        db.session.add(analysis)

        db.session.commit()

    return jsonify({

        "status": "stopped",

        "saved": bool(packets)
    })


# ============================================================
# LIVE PACKETS
# ============================================================

@app.route("/live/packets")
@login_required
def get_live_packets():

    packets = (
        live_sniffer.get_packets()
    )

    detector = ThreatDetector()

    threats = detector.analyze(
        packets
    )

    return jsonify({

        "active":
        live_sniffer.is_active(),

        "packets":
        packets[-50:],

        "total":
        len(packets),

        "threats":
        threats,

        "is_mock":
        live_sniffer.is_mock
    })


# ============================================================
# HISTORY
# ============================================================

@app.route("/history")
@login_required
def get_history():

    analyses = (
        Analysis.query
        .filter_by(
            user_id=current_user.id
        )
        .order_by(
            Analysis.timestamp.desc()
        )
        .all()
    )

    return jsonify([
        analysis.to_dict()
        for analysis in analyses
    ])


# ============================================================
# SINGLE ANALYSIS
# ============================================================

@app.route("/history/<int:analysis_id>")
@login_required
def get_single_analysis(
    analysis_id
):

    analysis = (
        Analysis.query
        .filter_by(
            id=analysis_id,
            user_id=current_user.id
        )
        .first()
    )

    if not analysis:

        return jsonify({
            "error":
            "Analysis not found"
        }), 404

    return jsonify(
        analysis.to_dict()
    )


# ============================================================
# DELETE ANALYSIS
# ============================================================

@app.route(
    "/history/<int:analysis_id>",
    methods=["DELETE"]
)
@login_required
def delete_analysis(
    analysis_id
):

    analysis = (
        Analysis.query
        .filter_by(
            id=analysis_id,
            user_id=current_user.id
        )
        .first()
    )

    if not analysis:

        return jsonify({
            "error":
            "Analysis not found"
        }), 404

    db.session.delete(
        analysis
    )

    db.session.commit()

    return jsonify({
        "message":
        "Analysis deleted successfully"
    })


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    app.run(
        debug=True,
        port=5000
    )