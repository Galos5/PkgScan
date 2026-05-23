from fastapi import FastAPI, Depends
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from models import ScanModel, ScanPackageModel, VulnerabilityCacheModel
from database import engine, get_db
import models

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="PkgScan Server")


class PackageInfo(BaseModel):
    name: str
    version: str
    ecosystem: str


class ScanRequest(BaseModel):
    endpoint_id: str
    packages: List[PackageInfo]


def check_package_against_osv(ecosystem: str, name: str, version: str) -> dict:
    url = "https://api.osv.dev/v1/query"
    ecosystem_mapping = {
        "npm": "npm",
        "pypi": "PyPI",
        "nuget": "NuGet",
        "go": "Go"
    }

    osv_ecosystem = ecosystem_mapping.get(ecosystem.lower(), ecosystem)
    payload = {
        "package": {"name": name, "ecosystem": osv_ecosystem},
        "version": version
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        response.raise_for_status()
        data = response.json()

        if not data or "vulns" not in data:
            return {"status": "SAFE", "details": "No known vulnerabilities found in OSV database."}

        first_vuln = data["vulns"][0]
        return {
            "status": "VULNERABLE",
            "details": f"{first_vuln.get('id', 'Unknown ID')}: {first_vuln.get('summary', 'No summary')}"
        }
    except Exception as e:
        return {"status": "UNKNOWN", "details": f"Failed to scan against OSV: {str(e)}"}


@app.get("/")
def read_root():
    return {"status": "PkgScan server is up and running!"}


@app.post("/api/scan")
def scan_dependencies(request: ScanRequest, db: Session = Depends(get_db)):
    new_scan = models.ScanModel(endpoint_id=request.endpoint_id)
    db.add(new_scan)
    db.flush()

    scan_results = []
    cache_ttl_limit = datetime.utcnow() - timedelta(hours=24)
    packages_to_query_online = []

    for pkg in request.packages:
        cache_key = f"{pkg.ecosystem.lower()}:{pkg.name.lower()}:{pkg.version}"
        cached_item = db.query(models.VulnerabilityCacheModel).filter(
            models.VulnerabilityCacheModel.package_key == cache_key,
            models.VulnerabilityCacheModel.last_scanned_at >= cache_ttl_limit
        ).first()

        if cached_item:
            scan_results.append({
                "pkg_object": pkg,
                "cache_key": cache_key,
                "status": cached_item.status,
                "details": cached_item.details
            })
        else:
            packages_to_query_online.append({
                "pkg_object": pkg,
                "cache_key": cache_key
            })

    if packages_to_query_online:
        def fetch_worker(item):
            pkg = item["pkg_object"]
            res = check_package_against_osv(pkg.ecosystem, pkg.name, pkg.version)
            return {
                "pkg_object": pkg,
                "cache_key": item["cache_key"],
                "status": res["status"],
                "details": res["details"]
            }

        with ThreadPoolExecutor(max_workers=15) as executor:
            online_results = list(executor.map(fetch_worker, packages_to_query_online))

        for res in online_results:
            scan_results.append(res)
            existing_cache = db.query(models.VulnerabilityCacheModel).filter_by(package_key=res["cache_key"]).first()
            if existing_cache:
                existing_cache.status = res["status"]
                existing_cache.details = res["details"]
                existing_cache.last_scanned_at = datetime.utcnow()
            else:
                new_cache_entry = models.VulnerabilityCacheModel(
                    package_key=res["cache_key"],
                    status=res["status"],
                    details=res["details"]
                )
                db.add(new_cache_entry)

    final_response_results = []
    for item in scan_results:
        pkg = item["pkg_object"]
        new_package = models.ScanPackageModel(
            scan_id=new_scan.id,
            name=pkg.name,
            version=pkg.version,
            ecosystem=pkg.ecosystem
        )
        db.add(new_package)

        final_response_results.append({
            "name": pkg.name,
            "version": pkg.version,
            "ecosystem": pkg.ecosystem,
            "status": item["status"],
            "details": item["details"]
        })

    db.commit()
    return {
        "status": "success",
        "scan_id": new_scan.id,
        "endpoint_id": request.endpoint_id,
        "results": final_response_results
    }


@app.get("/api/reports/{endpoint_id}")
def get_vulnerabilities_report(endpoint_id: str, db: Session = Depends(get_db)):
    latest_scan = db.query(ScanModel).filter(ScanModel.endpoint_id == endpoint_id).order_by(ScanModel.id.desc()).first()

    if not latest_scan:
        return {
            "endpoint_id": endpoint_id,
            "status": f"No scans found for endpoint: {endpoint_id}"
        }

    scan_packages = db.query(ScanPackageModel).filter(ScanPackageModel.scan_id == latest_scan.id).all()
    issues = []

    for pkg in scan_packages:
        cache_key = f"{pkg.ecosystem.lower()}:{pkg.name.lower()}:{pkg.version}"
        cache_item = db.query(VulnerabilityCacheModel).filter(VulnerabilityCacheModel.package_key == cache_key).first()

        if cache_item and cache_item.status == "VULNERABLE":
            issues.append({
                "name": pkg.name,
                "version": pkg.version,
                "ecosystem": pkg.ecosystem,
                "details": cache_item.details
            })

    return {
        "endpoint_id": endpoint_id,
        "scan_id": latest_scan.id,
        "scanned_at": latest_scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": len(issues),
        "vulnerabilities": issues
    }