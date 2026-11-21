"""
Cyber Attack Surface Monitoring & Vulnerability Intelligence System
Seed Data Script: Generates a realistic cybersecurity lab environment
"""

import os
import sys
from datetime import datetime, timedelta

# Ensure root directory is on python path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))

from app import create_app
from models import (
    db, User, Asset, Scan, ScanResult, CVERecord,
    Vulnerability, SecurityAlert, MonitoringSchedule, AuditLog, ReportRecord
)
from modules.cve_intelligence import CURATED_CVE_DATABASE, get_or_create_cve_record
from modules.risk_assessment import update_asset_risk_score
from modules.reports import generate_pdf_report

def seed_cyber_lab():
    app = create_app()
    with app.app_context():
        print("[*] Creating database tables...")
        db.create_all()

        # 1. Admin User
        admin = User.query.filter_by(username="admin").first()
        if not admin:
            admin = User(
                username="admin",
                email="admin@cybersec.corp",
                role="superadmin",
                is_active=True,
                created_at=datetime.utcnow() - timedelta(days=10)
            )
            admin.set_password("Admin123!456")
            db.session.add(admin)
            print("[+] Created Default Admin: 'admin' / 'Admin123!456'")
        else:
            print("[*] Admin user already exists.")

        # 2. Curated CVE Database Seeding
        print("[*] Pre-seeding Curated NIST CVE Knowledgebase...")
        cve_map = {}
        for item in CURATED_CVE_DATABASE:
            rec = get_or_create_cve_record(item)
            cve_map[rec.cve_id] = rec

        # 3. Assets Inventory Seeding
        assets_data = [
            {
                "target": "198.51.100.25",
                "name": "Prod-Web-Gateway-01",
                "asset_type": "IP",
                "criticality": "Critical",
                "environment": "Production",
                "is_monitored": True,
                "status": "Active"
            },
            {
                "target": "api.enterprise.corp",
                "name": "Public-API-Cluster",
                "asset_type": "Domain",
                "criticality": "High",
                "environment": "Production",
                "is_monitored": True,
                "status": "Active"
            },
            {
                "target": "10.0.4.15",
                "name": "Internal-Database-Master",
                "asset_type": "IP",
                "criticality": "High",
                "environment": "Internal",
                "is_monitored": True,
                "status": "Active"
            },
            {
                "target": "bastion.dmz.corp",
                "name": "DMZ-Bastion-Host",
                "asset_type": "Domain",
                "criticality": "Critical",
                "environment": "DMZ",
                "is_monitored": True,
                "status": "Active"
            },
            {
                "target": "172.16.50.10",
                "name": "Staging-Redis-Cache",
                "asset_type": "IP",
                "criticality": "Medium",
                "environment": "Staging",
                "is_monitored": True,
                "status": "Active"
            }
        ]

        created_assets = []
        for ad in assets_data:
            existing = Asset.query.filter_by(target=ad["target"]).first()
            if not existing:
                asset = Asset(
                    target=ad["target"],
                    name=ad["name"],
                    asset_type=ad["asset_type"],
                    criticality=ad["criticality"],
                    environment=ad["environment"],
                    is_monitored=ad["is_monitored"],
                    status=ad["status"],
                    created_at=datetime.utcnow() - timedelta(days=5)
                )
                db.session.add(asset)
                created_assets.append(asset)
            else:
                created_assets.append(existing)

        db.session.commit()
        print(f"[+] Verified {len(created_assets)} monitored digital assets.")

        # 4. Scans & Discovered Services
        scans_config = [
            {
                "asset": created_assets[0], # Prod-Web-Gateway-01 (198.51.100.25)
                "profile": "Standard",
                "services": [
                    {"port": 80, "proto": "tcp", "name": "http", "product": "Apache httpd", "ver": "2.4.49", "cve": "CVE-2021-41773", "conf": "High"},
                    {"port": 443, "proto": "tcp", "name": "https", "product": "Apache httpd", "ver": "2.4.49", "cve": "CVE-2021-42013", "conf": "High"},
                    {"port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH", "ver": "7.4p1", "cve": "CVE-2018-15473", "conf": "Medium"}
                ]
            },
            {
                "asset": created_assets[1], # Public-API-Cluster (api.enterprise.corp)
                "profile": "Quick",
                "services": [
                    {"port": 443, "proto": "tcp", "name": "https", "product": "nginx", "ver": "1.18.0", "cve": "CVE-2021-23017", "conf": "High"},
                    {"port": 80, "proto": "tcp", "name": "http", "product": "nginx", "ver": "1.18.0", "cve": "CVE-2021-23017", "conf": "Medium"}
                ]
            },
            {
                "asset": created_assets[2], # Internal-Database-Master (10.0.4.15)
                "profile": "Deep",
                "services": [
                    {"port": 3306, "proto": "tcp", "name": "mysql", "product": "MySQL", "ver": "5.7.33", "cve": "CVE-2021-2292", "conf": "High"},
                    {"port": 22, "proto": "tcp", "name": "ssh", "product": "OpenSSH", "ver": "8.2p1", "cve": "CVE-2020-14145", "conf": "Medium"}
                ]
            },
            {
                "asset": created_assets[4], # Staging-Redis-Cache (172.16.50.10)
                "profile": "Standard",
                "services": [
                    {"port": 6379, "proto": "tcp", "name": "redis", "product": "Redis", "ver": "5.0.7", "cve": "CVE-2022-0543", "conf": "High"}
                ]
            }
        ]

        if Scan.query.count() == 0:
            print("[*] Generating simulated scan baselines & findings...")
            for idx, sc in enumerate(scans_config):
                asset = sc["asset"]
                scan = Scan(
                    asset_id=asset.id,
                    target=asset.target,
                    profile=sc["profile"],
                    status="Completed",
                    started_at=datetime.utcnow() - timedelta(hours=48 - (idx * 8)),
                    completed_at=datetime.utcnow() - timedelta(hours=48 - (idx * 8)) + timedelta(seconds=14),
                    duration_seconds=14.2,
                    open_ports_count=len(sc["services"]),
                    raw_output=f"[*] Starting Security Scan against {asset.target} ({sc['profile']} profile)\n"
                               f"[+] Host is up (0.0024s latency).\n" +
                               "\n".join([f"    -> Discovered Port {s['port']}/{s['proto']} open: {s['product']} {s['ver']}" for s in sc["services"]]) +
                               f"\n[+] Scan completed: {len(sc['services'])} open ports identified.",
                    summary=f"Discovered {len(sc['services'])} exposed services on {asset.target}."
                )
                db.session.add(scan)
                db.session.flush()

                # Add ScanResults and Vulnerabilities
                vuln_count = 0
                for s in sc["services"]:
                    sr = ScanResult(
                        scan_id=scan.id,
                        asset_id=asset.id,
                        host=asset.target,
                        port=s["port"],
                        protocol=s["proto"],
                        state="open",
                        service_name=s["name"],
                        product=s["product"],
                        version=s["ver"],
                        banner=f"{s['product']}/{s['ver']}",
                        cpe=f"cpe:2.3:a:{s['product'].lower()}:{s['product'].lower()}:{s['ver']}:*:*:*:*:*:*:*",
                        discovered_at=scan.started_at
                    )
                    db.session.add(sr)
                    db.session.flush()

                    # Match CVE
                    cve_rec = cve_map.get(s["cve"])
                    if cve_rec:
                        vuln = Vulnerability(
                            asset_id=asset.id,
                            scan_result_id=sr.id,
                            cve_record_id=cve_rec.id,
                            confidence=s["conf"],
                            status="Open",
                            risk_score=round(cve_rec.cvss_score * (1.0 if s["conf"] == "High" else 0.8), 1),
                            remediation=cve_rec.description[:80] + "... Update to latest stable patch.",
                            discovered_at=scan.started_at
                        )
                        db.session.add(vuln)
                        vuln_count += 1

                scan.vulns_count = vuln_count
                asset.last_scanned_at = scan.completed_at
                db.session.commit()
                update_asset_risk_score(asset.id)

            print("[+] Populated realistic scans, open ports, and correlated vulnerabilities.")

        # 5. Security Alerts (Attack Surface Drift)
        if SecurityAlert.query.count() == 0:
            alerts_data = [
                {
                    "asset": created_assets[0],
                    "type": "NEW_PORT",
                    "severity": "Critical",
                    "title": f"New Open Port Detected: 80/tcp on {created_assets[0].name}",
                    "message": f"Attack surface expanded on {created_assets[0].target}. New service Apache httpd 2.4.49 listening.",
                    "details": "Port: 80/tcp | Product: Apache httpd 2.4.49 | CVE: CVE-2021-41773 (CVSS 9.8)",
                    "status": "Unread"
                },
                {
                    "asset": created_assets[4],
                    "type": "NEW_PORT",
                    "severity": "Critical",
                    "title": f"Exposed Database Service: 6379/tcp on {created_assets[4].name}",
                    "message": "Unprotected Redis cache service detected listening on public interface.",
                    "details": "Port: 6379/tcp | Version: Redis 5.0.7 | CVE: CVE-2022-0543 (CVSS 10.0)",
                    "status": "Unread"
                },
                {
                    "asset": created_assets[1],
                    "type": "SERVICE_CHANGED",
                    "severity": "Medium",
                    "title": f"Service Modified: Port 443 on {created_assets[1].name}",
                    "message": "Detected web server software version change on api.enterprise.corp:443.",
                    "details": "Previous: nginx 1.16.1 | Current: nginx 1.18.0",
                    "status": "Acknowledged"
                },
                {
                    "asset": created_assets[2],
                    "type": "BASELINE_ESTABLISHED",
                    "severity": "Info",
                    "title": f"Baseline Established: {created_assets[2].name}",
                    "message": f"Initial scan baseline completed for {created_assets[2].target}. 2 listening ports recorded.",
                    "details": "Ports: 3306, 22",
                    "status": "Resolved"
                }
            ]
            for a in alerts_data:
                alert = SecurityAlert(
                    asset_id=a["asset"].id,
                    alert_type=a["type"],
                    severity=a["severity"],
                    title=a["title"],
                    message=a["message"],
                    details=a["details"],
                    status=a["status"],
                    created_at=datetime.utcnow() - timedelta(hours=6)
                )
                db.session.add(alert)
            db.session.commit()
            print("[+] Seeded Attack Surface drift security alerts.")

        # 6. Monitoring Schedules
        if MonitoringSchedule.query.count() == 0:
            schedules = [
                MonitoringSchedule(
                    name="Daily Production Perimeter Assessment",
                    asset_id=created_assets[0].id,
                    scan_profile="Standard",
                    frequency="daily",
                    interval_hours=24,
                    is_active=True,
                    next_run=datetime.utcnow() + timedelta(hours=18),
                    created_at=datetime.utcnow() - timedelta(days=2)
                ),
                MonitoringSchedule(
                    name="Continuous DMZ Drift Check",
                    asset_id=created_assets[3].id,
                    scan_profile="Quick",
                    frequency="hourly",
                    interval_hours=1,
                    is_active=True,
                    next_run=datetime.utcnow() + timedelta(minutes=45),
                    created_at=datetime.utcnow() - timedelta(days=1)
                )
            ]
            for s in schedules:
                db.session.add(s)
            db.session.commit()
            print("[+] Seeded APScheduler recurring monitoring jobs.")

        # 7. Initial Report Generation
        if ReportRecord.query.count() == 0:
            print("[*] Generating initial executive PDF security assessment...")
            try:
                generate_pdf_report(
                    asset_id=None,
                    report_title="Infrastructure Attack Surface & Threat Intelligence Assessment",
                    generated_by="SecOps Lead (admin)"
                )
                print("[+] Pre-generated initial executive PDF report.")
            except Exception as e:
                print(f"[!] PDF generation notice: {e}")

        # 8. Audit Logs
        if AuditLog.query.count() == 0:
            logs = [
                AuditLog(username="admin", action="SYSTEM_INITIALIZED", target="SOC Core", details="Cyber Security Operations Center initialized with full module suite"),
                AuditLog(username="admin", action="ASSET_ADDED", target="198.51.100.25", details="Registered Prod-Web-Gateway-01 under Tier-1 monitoring"),
                AuditLog(username="admin", action="SCAN_LAUNCHED", target="198.51.100.25", details="Executed Standard Service Scan #1"),
                AuditLog(username="admin", action="REPORT_GENERATED", target="Full Scope", details="Exported initial executive assessment PDF report"),
            ]
            for l in logs:
                db.session.add(l)
            db.session.commit()

        print("\n=======================================================")
        print("  CYBER SOC LAB SEEDED SUCCESSFULLY!")
        print("  Default Admin Login:")
        print("    Username: admin")
        print("    Password: Admin123!456")
        print("=======================================================\n")

if __name__ == '__main__':
    seed_cyber_lab()
