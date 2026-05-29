from fastapi import FastAPI, Depends, HTTPException
from pydantic import BaseModel
from typing import List
from sqlalchemy.orm import Session
import requests
from datetime import datetime, timedelta
from concurrent.futures import ThreadPoolExecutor
from models import ScanModel, ScanPackageModel, VulnerabilityCacheModel
from database import engine, get_db
import models
from fastapi.middleware.cors import CORSMiddleware

models.Base.metadata.create_all(bind=engine)

app = FastAPI(title="PkgScan Server")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


class PackageInfo(BaseModel):
    name: str
    version: str
    ecosystem: str


class ScanRequest(BaseModel):
    endpoint_id: str
    packages: List[PackageInfo]


def is_version_vulnerable_pure(ecosystem: str, name: str, version: str) -> bool:
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem}
    }
    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "vulns" in data and len(data["vulns"]) > 0:
                return True
    except Exception as e:
        print(f"Error doing pure vulnerability check: {e}")
    return False


def check_package_against_osv(ecosystem: str, name: str, version: str):
    url = "https://api.osv.dev/v1/query"
    payload = {
        "version": version,
        "package": {"name": name, "ecosystem": ecosystem}
    }

    try:
        response = requests.post(url, json=payload, timeout=5)
        if response.status_code == 200:
            data = response.json()
            if "vulns" in data and len(data["vulns"]) > 0:
                vuln_entries = data["vulns"]
                details_list = [v.get("summary", v.get("details", "")) for v in vuln_entries]
                combined_details = " | ".join(details_list)

                has_any_fix_at_all = False
                patched_version = None

                for vuln in vuln_entries:
                    for affected in vuln.get("affected", []):
                        for r in affected.get("ranges", []):
                            for event in r.get("events", []):
                                if "fixed" in event:
                                    potential_fix = event["fixed"]
                                    has_any_fix_at_all = True

                                    is_unstable = any(
                                        keyword in potential_fix.lower() for keyword in ["beta", "alpha", "rc", "pre"])
                                    if is_unstable:
                                        continue

                                    is_fix_vulnerable = is_version_vulnerable_pure(ecosystem, name, potential_fix)
                                    if is_fix_vulnerable:
                                        continue

                                    patched_version = potential_fix
                                    break
                            if patched_version:
                                break
                        if patched_version:
                            break
                    if patched_version:
                        break

                if has_any_fix_at_all and not patched_version:
                    return "VULNERABLE", combined_details, "UNSAFE_FIX_FOUND"

                return "VULNERABLE", combined_details, patched_version

            return "SAFE", "No vulnerabilities found", None
    except Exception as e:
        print(f"Error querying OSV: {e}")
        return "ERROR", "Error querying OSV", None

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
                "details": cached_item.details,
                "patched_version": cached_item.patched_version
            })
        else:
            packages_to_query_online.append({
                "pkg_object": pkg,
                "cache_key": cache_key
            })

    if packages_to_query_online:
        def fetch_worker(item):
            pkg = item["pkg_object"]
            status, details, patched_version = check_package_against_osv(pkg.ecosystem, pkg.name, pkg.version)
            return {
                "pkg_object": pkg,
                "cache_key": item["cache_key"],
                "status": status,
                "details": details,
                "patched_version": patched_version
            }

        with ThreadPoolExecutor(max_workers=15) as executor:
            online_results = list(executor.map(fetch_worker, packages_to_query_online))

        for res in online_results:
            scan_results.append(res)
            existing_cache = db.query(models.VulnerabilityCacheModel).filter_by(package_key=res["cache_key"]).first()
            if existing_cache:
                existing_cache.status = res["status"]
                existing_cache.details = res["details"]
                existing_cache.patched_version = res["patched_version"]
                existing_cache.last_scanned_at = datetime.utcnow()
            else:
                new_cache_entry = models.VulnerabilityCacheModel(
                    package_key=res["cache_key"],
                    status=res["status"],
                    details=res["details"],
                    patched_version=res["patched_version"]
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
            "details": item["details"],
            "patched_version": item["patched_version"]
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
                "details": cache_item.details,
                "patched_version": cache_item.patched_version
            })

    return {
        "endpoint_id": endpoint_id,
        "scan_id": latest_scan.id,
        "scanned_at": latest_scan.created_at.strftime("%Y-%m-%d %H:%M:%S"),
        "total_vulnerabilities": len(issues),
        "vulnerabilities": issues
    }