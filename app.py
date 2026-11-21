import os
from datetime import datetime
from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, login_required, current_user
from sqlalchemy import func

from config import Config
from models import (
    db, User, AuditLog, Asset, Scan, ScanResult,
    CVERecord, Vulnerability, SecurityAlert, MonitoringSchedule, ReportRecord
)
from modules.auth import auth_bp, log_audit
from modules.assets import assets_bp
from modules.scanner import scanner_bp, get_nmap_info
from modules.cve_intelligence import cve_bp
from modules.monitoring import monitoring_bp, init_scheduler
from modules.alerts import alerts_bp
from modules.reports import reports_bp
from modules.risk_assessment import get_infrastructure_risk_summary

def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)

    # Initialize extensions
    os.makedirs(os.path.dirname(app.config["DATABASE_PATH"]), exist_ok=True)
    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message_category = 'info'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # Context processors for all templates
    @app.context_processor
    def inject_global_data():
        unread_alerts_count = 0
        if current_user.is_authenticated:
            unread_alerts_count = SecurityAlert.query.filter_by(status='Unread').count()
        return {
            "unread_alerts_count": unread_alerts_count,
            "now": datetime.utcnow()
        }

    # Register blueprints
    app.register_blueprint(auth_bp)
    app.register_blueprint(assets_bp)
    app.register_blueprint(scanner_bp)
    app.register_blueprint(cve_bp)
    app.register_blueprint(monitoring_bp)
    app.register_blueprint(alerts_bp)
    app.register_blueprint(reports_bp)

    # Root redirect
    @app.route('/')
    def index():
        if current_user.is_authenticated:
            return redirect(url_for('dashboard'))
        return redirect(url_for('auth.login'))

    # Main Security Operations Center Dashboard
    @app.route('/dashboard')
    @login_required
    def dashboard():
        summary = get_infrastructure_risk_summary()

        # Recent alerts & scans
        recent_alerts = SecurityAlert.query.order_by(SecurityAlert.created_at.desc()).limit(6).all()
        recent_scans = Scan.query.order_by(Scan.started_at.desc()).limit(5).all()
        top_critical_assets = Asset.query.order_by(Asset.risk_score.desc()).limit(5).all()

        return render_template(
            'dashboard.html',
            summary=summary,
            recent_alerts=recent_alerts,
            recent_scans=recent_scans,
            top_critical_assets=top_critical_assets
        )

    # Settings and Audit Logs Page
    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def settings_page():
        nmap_info = get_nmap_info()

        if request.method == 'POST':
            nvd_key = request.form.get('nvd_api_key', '').strip()
            nmap_custom = request.form.get('nmap_path', '').strip()
            timeout = request.form.get('scan_timeout', '300').strip()

            if nvd_key is not None:
                Config.NVD_API_KEY = nvd_key
            if nmap_custom:
                Config.NMAP_PATH = nmap_custom
            if timeout.isdigit():
                Config.SCAN_DEFAULT_TIMEOUT = int(timeout)

            log_audit("SETTINGS_UPDATED", details=f"Updated Nmap path: {Config.NMAP_PATH}, Timeout: {Config.SCAN_DEFAULT_TIMEOUT}")
            flash("System configuration updated successfully.", "success")
            return redirect(url_for('settings_page'))

        # Fetch recent audit logs
        logs = AuditLog.query.order_by(AuditLog.timestamp.desc()).limit(50).all()

        return render_template(
            'settings.html',
            nmap_info=nmap_info,
            current_config={
                "nvd_api_key": Config.NVD_API_KEY,
                "nmap_path": Config.NMAP_PATH,
                "scan_timeout": Config.SCAN_DEFAULT_TIMEOUT,
                "database_uri": Config.SQLALCHEMY_DATABASE_URI
            },
            logs=logs
        )

    # API Endpoint for Dashboard Chart.js Visualizations
    @app.route('/api/dashboard-charts')
    @login_required
    def api_dashboard_charts():
        # 1. Vulnerability Severity Distribution
        sev_counts = {
            "Critical": Vulnerability.query.join(CVERecord).filter(CVERecord.severity == 'Critical', Vulnerability.status != 'Resolved').count(),
            "High": Vulnerability.query.join(CVERecord).filter(CVERecord.severity == 'High', Vulnerability.status != 'Resolved').count(),
            "Medium": Vulnerability.query.join(CVERecord).filter(CVERecord.severity == 'Medium', Vulnerability.status != 'Resolved').count(),
            "Low": Vulnerability.query.join(CVERecord).filter(CVERecord.severity == 'Low', Vulnerability.status != 'Resolved').count(),
        }

        # 2. Top Exposed Ports
        port_results = (
            db.session.query(ScanResult.port, ScanResult.service_name, func.count(ScanResult.id))
            .filter(ScanResult.state == 'open')
            .group_by(ScanResult.port, ScanResult.service_name)
            .order_by(func.count(ScanResult.id).desc())
            .limit(6)
            .all()
        )
        ports_labels = [f"Port {p[0]} ({p[1]})" for p in port_results] or ["Port 80 (http)", "Port 443 (https)", "Port 22 (ssh)"]
        ports_data = [p[2] for p in port_results] or [1, 1, 1]

        # 3. Asset Risk Comparison
        assets = Asset.query.order_by(Asset.risk_score.desc()).limit(6).all()
        asset_names = [a.name for a in assets] or ["Demo Asset"]
        asset_scores = [round(a.risk_score, 1) for a in assets] or [5.0]

        # 4. Historical Scan Trend (Latest 7 Scans)
        scans = Scan.query.filter_by(status='Completed').order_by(Scan.started_at.desc()).limit(7).all()
        scans = list(reversed(scans))
        scan_labels = [s.started_at.strftime("%m-%d %H:%M") for s in scans] or ["Scan 1", "Scan 2", "Scan 3"]
        scan_ports = [s.open_ports_count for s in scans] or [3, 4, 4]
        scan_vulns = [s.vulns_count for s in scans] or [2, 3, 3]

        return jsonify({
            "severities": sev_counts,
            "ports": {
                "labels": ports_labels,
                "data": ports_data
            },
            "assets_risk": {
                "labels": asset_names,
                "data": asset_scores
            },
            "scan_trend": {
                "labels": scan_labels,
                "ports": scan_ports,
                "vulns": scan_vulns
            }
        })

    # Error Handlers
    @app.errorhandler(404)
    def not_found_error(error):
        return render_template('base.html', error_code=404, error_message="Security resource not found."), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return render_template('base.html', error_code=500, error_message="Internal Security Engine error."), 500

    return app


app = create_app()

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        init_scheduler(app)
    app.run(host='0.0.0.0', port=5000, debug=True)
