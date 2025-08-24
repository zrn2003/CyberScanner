from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import nmap
import socket
import asyncio
import json
import uuid
from datetime import datetime
from typing import List, Dict, Optional
import threading
import time
from motor.motor_asyncio import AsyncIOMotorClient
from bson import ObjectId

app = FastAPI(
    title="Advanced Port Scanner & Vulnerability Detector",
    description="A comprehensive API for network scanning and vulnerability assessment",
    version="1.0.0"
)

# CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://localhost:3000"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Predefined port ranges
WELL_KNOWN_PORTS = {
    "common_services": "21,22,23,25,53,80,110,143,443,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443",
    "web_services": "80,443,8080,8443,3000,5000,8000,9000",
    "database_services": "1433,1521,3306,5432,6379,27017,9200",
    "mail_services": "25,110,143,465,587,993,995",
    "file_services": "21,22,139,445,2049",
    "remote_access": "22,23,3389,5900,5901,5902",
    "gaming_services": "25565,27015,27016,27017,27018,27019,27020,27021,27022,27023,27024,27025",
    "media_services": "554,1935,8000,8001,8002,8003,8004,8005,8006,8007,8008,8009"
}

# Data models
class ScanRequest(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    ports: str = Field(default="common_services", description="Port range to scan (e.g., 'common_services', '1-1000', or '80,443,8080')")
    scan_type: str = Field(default="tcp", description="Scan type: tcp or udp")
    timeout: int = Field(default=5, description="Timeout in seconds")

class VulnerabilityRequest(BaseModel):
    target: str = Field(..., description="Target IP address or hostname")
    ports: List[int] = Field(default=[80, 443, 22, 21, 23, 25, 53, 110, 143, 993, 995], description="Ports to check for vulnerabilities")

class ScanResult(BaseModel):
    scan_id: str
    target: str
    status: str
    start_time: str
    end_time: Optional[str] = None
    ports: List[Dict] = []
    vulnerabilities: List[Dict] = []
    summary: Dict = {}

# MongoDB Configuration
MONGODB_URL = "mongodb+srv://root:root@project03.pezjfqu.mongodb.net/?retryWrites=true&w=majority&appName=project03"
DATABASE_NAME = "cyberscanner"
COLLECTION_NAME = "scan_results"

# MongoDB client
mongodb_client: Optional[AsyncIOMotorClient] = None
database = None
collection = None

# Global storage for active scans (in-memory for real-time tracking)
active_scans: Dict[str, bool] = {}

# Initialize nmap scanner
try:
    nm = nmap.PortScanner()
except Exception as e:
    print(f"Warning: nmap not available: {e}")
    nm = None

async def connect_to_mongodb():
    """Connect to MongoDB"""
    global mongodb_client, database, collection
    try:
        print(f"🔄 Connecting to MongoDB: {DATABASE_NAME}.{COLLECTION_NAME}")
        mongodb_client = AsyncIOMotorClient(MONGODB_URL)
        database = mongodb_client[DATABASE_NAME]
        collection = database[COLLECTION_NAME]
        
        # Test connection
        await mongodb_client.admin.command('ping')
        print("✅ Connected to MongoDB successfully!")
        print(f"📊 Database: {DATABASE_NAME}")
        print(f"📁 Collection: {COLLECTION_NAME}")
        
        # Create indexes for better performance
        try:
            await collection.create_index("scan_id", unique=True)
            await collection.create_index("target")
            await collection.create_index("start_time")
            await collection.create_index("status")
            print("🔍 Database indexes created successfully")
        except Exception as index_error:
            print(f"⚠️ Warning: Could not create indexes: {index_error}")
        
    except Exception as e:
        print(f"❌ Failed to connect to MongoDB: {e}")
        mongodb_client = None
        database = None
        collection = None

async def close_mongodb_connection():
    """Close MongoDB connection"""
    global mongodb_client
    if mongodb_client:
        mongodb_client.close()
        print("MongoDB connection closed")

async def save_scan_result(scan_result: ScanResult):
    """Save scan result to MongoDB"""
    if collection is None:
        print("Warning: MongoDB not connected, cannot save scan result")
        return False
    
    try:
        # Convert to dict and handle ObjectId
        scan_data = scan_result.dict()
        scan_data["_id"] = ObjectId()  # Generate new ObjectId
        scan_data["created_at"] = datetime.now()
        
        await collection.insert_one(scan_data)
        print(f"✅ Scan result saved successfully for {scan_result.target}")
        return True
    except Exception as e:
        print(f"❌ Error saving scan result: {e}")
        return False

async def get_scan_result(scan_id: str):
    """Get scan result from MongoDB"""
    if collection is None:
        return None
    
    try:
        result = await collection.find_one({"scan_id": scan_id})
        if result:
            # Remove MongoDB-specific fields
            result.pop("_id", None)
            result.pop("created_at", None)
        return result
    except Exception as e:
        print(f"Error getting scan result: {e}")
        return None

async def update_scan_result(scan_id: str, update_data: Dict):
    """Update scan result in MongoDB"""
    if collection is None:
        return False
    
    try:
        update_data["updated_at"] = datetime.now()
        result = await collection.update_one(
            {"scan_id": scan_id},
            {"$set": update_data}
        )
        return result.modified_count > 0
    except Exception as e:
        print(f"Error updating scan result: {e}")
        return False

async def list_all_scans():
    """List all scans from MongoDB"""
    if collection is None:
        print("Warning: MongoDB collection not available")
        return {"scans": [], "message": "Database not connected", "total": 0}
    
    try:
        print(f"Attempting to list scans from collection: {collection.name}")
        cursor = collection.find({}, {
            "scan_id": 1,
            "target": 1,
            "status": 1,
            "start_time": 1,
            "end_time": 1,
            "created_at": 1
        }).sort("created_at", -1)  # Most recent first
        
        scans = []
        async for document in cursor:
            # Remove MongoDB-specific fields
            document.pop("_id", None)
            scans.append(document)
        
        print(f"Successfully retrieved {len(scans)} scans")
        
        if len(scans) == 0:
            return {"scans": [], "message": "No scan data available yet", "total": 0}
        else:
            return {"scans": scans, "message": f"Found {len(scans)} scans", "total": len(scans)}
            
    except Exception as e:
        print(f"Error listing scans: {e}")
        print(f"Collection status: {collection is not None}")
        return {"scans": [], "message": f"Error retrieving scans: {str(e)}", "total": 0}

async def delete_scan_result(scan_id: str):
    """Delete scan result from MongoDB"""
    if collection is None:
        return False
    
    try:
        result = await collection.delete_one({"scan_id": scan_id})
        return result.deleted_count > 0
    except Exception as e:
        print(f"Error deleting scan result: {e}")
        return False

def get_common_vulnerabilities(port: int, service: str) -> List[Dict]:
    """Get comprehensive vulnerabilities for known services with remediation advice"""
    vulnerabilities = []
    
    # SSH (Port 22)
    if port == 22 and "ssh" in service.lower():
        vulnerabilities.extend([
            {
                "type": "Weak SSH Configuration", 
                "severity": "High", 
                "description": "SSH service with weak security settings",
                "attack_vector": "Brute force attacks, weak key exchange",
                "remediation": "Use strong ciphers, disable root login, implement key-based authentication, use fail2ban"
            },
            {
                "type": "SSH Version Disclosure", 
                "severity": "Medium", 
                "description": "SSH version information exposed to attackers",
                "attack_vector": "Version-specific exploit targeting",
                "remediation": "Hide SSH banner, keep SSH updated, use security patches"
            },
            {
                "type": "Default SSH Credentials", 
                "severity": "Critical", 
                "description": "Default or weak SSH credentials",
                "attack_vector": "Credential stuffing, dictionary attacks",
                "remediation": "Change default passwords, use strong authentication, implement 2FA"
            }
        ])
    
    # HTTP (Port 80)
    elif port == 80 and "http" in service.lower():
        vulnerabilities.extend([
            {
                "type": "HTTP Information Disclosure", 
                "severity": "Medium", 
                "description": "Sensitive information exposed in HTTP headers",
                "attack_vector": "Information gathering, reconnaissance",
                "remediation": "Remove server banners, hide version info, secure headers"
            },
            {
                "type": "Directory Traversal", 
                "severity": "High", 
                "description": "Potential directory traversal vulnerability",
                "attack_vector": "Path manipulation, file access",
                "remediation": "Validate file paths, use whitelist approach, implement proper access controls"
            },
            {
                "type": "SQL Injection", 
                "severity": "Critical", 
                "description": "Potential SQL injection vulnerabilities",
                "attack_vector": "Malicious SQL queries, data extraction",
                "remediation": "Use parameterized queries, input validation, WAF protection"
            },
            {
                "type": "Cross-Site Scripting (XSS)", 
                "severity": "High", 
                "description": "Potential XSS vulnerabilities",
                "attack_vector": "Malicious script injection",
                "remediation": "Input sanitization, output encoding, CSP headers"
            }
        ])
    
    # HTTPS (Port 443)
    elif port == 443 and "https" in service.lower():
        vulnerabilities.extend([
            {
                "type": "SSL/TLS Configuration", 
                "severity": "Medium", 
                "description": "Weak SSL/TLS configuration",
                "attack_vector": "Man-in-the-middle attacks, downgrade attacks",
                "remediation": "Use TLS 1.3, disable weak ciphers, proper certificate management"
            },
            {
                "type": "Weak Ciphers", 
                "severity": "Medium", 
                "description": "Weak encryption ciphers enabled",
                "attack_vector": "Cryptographic attacks, data interception",
                "remediation": "Disable RC4, DES, 3DES, use AES-256, implement perfect forward secrecy"
            },
            {
                "type": "Certificate Issues", 
                "severity": "High", 
                "description": "SSL certificate problems",
                "attack_vector": "Certificate spoofing, man-in-the-middle",
                "remediation": "Valid certificates, proper CA validation, certificate transparency"
            }
        ])
    
    # FTP (Port 21)
    elif port == 21 and "ftp" in service.lower():
        vulnerabilities.extend([
            {
                "type": "Anonymous FTP Access", 
                "severity": "Critical", 
                "description": "Anonymous FTP access enabled",
                "attack_vector": "Unauthorized file access, data theft",
                "remediation": "Disable anonymous access, require authentication, use SFTP instead"
            },
            {
                "type": "FTP Banner Grabbing", 
                "severity": "Low", 
                "description": "FTP service information exposed",
                "attack_vector": "Information gathering, version targeting",
                "remediation": "Hide FTP banner, use SFTP, implement access controls"
            },
            {
                "type": "FTP Credential Exposure", 
                "severity": "High", 
                "description": "FTP credentials transmitted in plaintext",
                "attack_vector": "Credential sniffing, man-in-the-middle",
                "remediation": "Use SFTP/FTPS, implement VPN, encrypt credentials"
            }
        ])
    
    # Telnet (Port 23)
    elif port == 23:
        vulnerabilities.extend([
            {
                "type": "Telnet Service Active", 
                "severity": "Critical", 
                "description": "Telnet service running (insecure)",
                "attack_vector": "Credential sniffing, man-in-the-middle attacks",
                "remediation": "Disable telnet, use SSH instead, implement network segmentation"
            },
            {
                "type": "Plaintext Communication", 
                "severity": "High", 
                "description": "All communication in plaintext",
                "attack_vector": "Data interception, credential theft",
                "remediation": "Replace with encrypted alternatives, implement VPN"
            }
        ])
    
    # SMTP (Port 25)
    elif port == 25:
        vulnerabilities.extend([
            {
                "type": "Open SMTP Relay", 
                "severity": "High", 
                "description": "SMTP relay not properly configured",
                "attack_vector": "Spam attacks, email spoofing",
                "remediation": "Restrict relay access, implement authentication, use SPF/DKIM"
            },
            {
                "type": "SMTP Banner Information", 
                "severity": "Low", 
                "description": "SMTP server information exposed",
                "attack_vector": "Information gathering, targeted attacks",
                "remediation": "Hide server banners, implement rate limiting"
            }
        ])
    
    # DNS (Port 53)
    elif port == 53:
        vulnerabilities.extend([
            {
                "type": "DNS Zone Transfer", 
                "severity": "Medium", 
                "description": "DNS zone transfer allowed",
                "attack_vector": "Network reconnaissance, information gathering",
                "remediation": "Restrict zone transfers, implement access controls"
            },
            {
                "type": "DNS Amplification", 
                "severity": "High", 
                "description": "DNS service vulnerable to amplification attacks",
                "attack_vector": "DDoS attacks, network flooding",
                "remediation": "Implement rate limiting, disable recursion for external queries"
            }
        ])
    
    # POP3 (Port 110)
    elif port == 110:
        vulnerabilities.extend([
            {
                "type": "Plaintext Authentication", 
                "severity": "High", 
                "description": "POP3 authentication in plaintext",
                "attack_vector": "Credential sniffing, man-in-the-middle",
                "remediation": "Use POP3S (encrypted), implement VPN, 2FA"
            }
        ])
    
    # IMAP (Port 143)
    elif port == 143:
        vulnerabilities.extend([
            {
                "type": "Plaintext Authentication", 
                "severity": "High", 
                "description": "IMAP authentication in plaintext",
                "attack_vector": "Credential sniffing, man-in-the-middle",
                "remediation": "Use IMAPS (encrypted), implement VPN, 2FA"
            }
        ])
    
    # SMB/NetBIOS (Port 139)
    elif port == 139:
        vulnerabilities.extend([
            {
                "type": "SMB Version 1", 
                "severity": "Critical", 
                "description": "SMBv1 enabled (vulnerable to EternalBlue)",
                "attack_vector": "WannaCry, EternalBlue exploits",
                "remediation": "Disable SMBv1, use SMBv3, apply security patches"
            },
            {
                "type": "Guest Access", 
                "severity": "High", 
                "description": "Guest access enabled on SMB shares",
                "attack_vector": "Unauthorized file access, data theft",
                "remediation": "Disable guest access, require authentication, implement ACLs"
            }
        ])
    
    # SMB (Port 445)
    elif port == 445:
        vulnerabilities.extend([
            {
                "type": "SMB Null Sessions", 
                "severity": "High", 
                "description": "Null sessions allowed on SMB",
                "attack_vector": "Anonymous access, information gathering",
                "remediation": "Disable null sessions, require authentication, implement access controls"
            },
            {
                "type": "SMB Signing Disabled", 
                "severity": "Medium", 
                "description": "SMB message signing not enforced",
                "attack_vector": "Man-in-the-middle attacks, session hijacking",
                "remediation": "Enable SMB signing, use SMBv3, implement encryption"
            }
        ])
    
    # SQL Server (Port 1433)
    elif port == 1433:
        vulnerabilities.extend([
            {
                "type": "SQL Server Exposed", 
                "severity": "High", 
                "description": "SQL Server accessible from network",
                "attack_vector": "SQL injection, brute force, data theft",
                "remediation": "Use firewall rules, VPN access, implement strong authentication"
            },
            {
                "type": "Default Credentials", 
                "severity": "Critical", 
                "description": "Default SQL Server credentials",
                "attack_vector": "Credential attacks, unauthorized access",
                "remediation": "Change default passwords, use strong authentication, implement least privilege"
            }
        ])
    
    # Oracle Database (Port 1521)
    elif port == 1521:
        vulnerabilities.extend([
            {
                "type": "Oracle TNS Listener", 
                "severity": "High", 
                "description": "Oracle TNS listener exposed",
                "attack_vector": "TNS poisoning, unauthorized access",
                "remediation": "Restrict network access, implement authentication, use firewall rules"
            }
        ])
    
    # MySQL (Port 3306)
    elif port == 3306:
        vulnerabilities.extend([
            {
                "type": "MySQL Exposed", 
                "severity": "High", 
                "description": "MySQL database accessible from network",
                "attack_vector": "SQL injection, brute force, data theft",
                "remediation": "Use firewall rules, VPN access, implement strong authentication"
            },
            {
                "type": "Default Credentials", 
                "severity": "Critical", 
                "description": "Default MySQL credentials",
                "attack_vector": "Credential attacks, unauthorized access",
                "remediation": "Change default passwords, use strong authentication, implement least privilege"
            }
        ])
    
    # RDP (Port 3389)
    elif port == 3389:
        vulnerabilities.extend([
            {
                "type": "RDP Exposed", 
                "severity": "High", 
                "description": "Remote Desktop accessible from network",
                "attack_vector": "Brute force attacks, credential stuffing",
                "remediation": "Use firewall rules, VPN access, implement 2FA, use strong passwords"
            },
            {
                "type": "RDP BlueKeep", 
                "severity": "Critical", 
                "description": "Vulnerable to BlueKeep exploit (CVE-2019-0708)",
                "attack_vector": "Remote code execution, worm propagation",
                "remediation": "Apply security patches, disable RDP if not needed, use VPN"
            }
        ])
    
    # PostgreSQL (Port 5432)
    elif port == 5432:
        vulnerabilities.extend([
            {
                "type": "PostgreSQL Exposed", 
                "severity": "High", 
                "description": "PostgreSQL database accessible from network",
                "attack_vector": "SQL injection, brute force, data theft",
                "remediation": "Use firewall rules, VPN access, implement strong authentication"
            }
        ])
    
    # VNC (Port 5900-5902)
    elif port in [5900, 5901, 5902]:
        vulnerabilities.extend([
            {
                "type": "VNC Exposed", 
                "severity": "High", 
                "description": "VNC service accessible from network",
                "attack_vector": "Brute force attacks, screen capture",
                "remediation": "Use firewall rules, VPN access, implement strong authentication, use VNC over SSH"
            },
            {
                "type": "Weak VNC Authentication", 
                "severity": "Critical", 
                "description": "VNC with weak or no authentication",
                "attack_vector": "Unauthorized access, screen capture",
                "remediation": "Implement strong passwords, use VNC over SSH tunnel, restrict access"
            }
        ])
    
    # Redis (Port 6379)
    elif port == 6379:
        vulnerabilities.extend([
            {
                "type": "Redis Exposed", 
                "severity": "High", 
                "description": "Redis database accessible from network",
                "attack_vector": "Unauthorized access, data theft, ransomware",
                "remediation": "Use firewall rules, bind to localhost, implement authentication, disable dangerous commands"
            }
        ])
    
    # Web Development Ports (3000, 5000, 8000, 9000)
    elif port in [3000, 5000, 8000, 9000]:
        vulnerabilities.extend([
            {
                "type": "Development Server Exposed", 
                "severity": "Medium", 
                "description": "Development server accessible from network",
                "attack_vector": "Information disclosure, potential vulnerabilities",
                "remediation": "Use firewall rules, bind to localhost, implement authentication, use production servers"
            }
        ])
    
    # Gaming Ports (25565, 27015-27025)
    elif port in [25565] + list(range(27015, 27026)):
        vulnerabilities.extend([
            {
                "type": "Gaming Server Exposed", 
                "severity": "Medium", 
                "description": "Gaming server accessible from network",
                "attack_vector": "DDoS attacks, server flooding, cheating",
                "remediation": "Use DDoS protection, implement rate limiting, monitor for abuse, use VPN if needed"
            }
        ])
    
    # Media Streaming Ports (554, 1935, 8000-8009)
    elif port in [554, 1935] + list(range(8000, 8010)):
        vulnerabilities.extend([
            {
                "type": "Media Server Exposed", 
                "severity": "Medium", 
                "description": "Media streaming server accessible from network",
                "attack_vector": "Bandwidth abuse, unauthorized access, content theft",
                "remediation": "Use firewall rules, implement authentication, rate limiting, content protection"
            }
        ])
    
    # NFS (Port 2049)
    elif port == 2049:
        vulnerabilities.extend([
            {
                "type": "NFS Exposed", 
                "severity": "High", 
                "description": "NFS service accessible from network",
                "attack_vector": "Unauthorized file access, data theft",
                "remediation": "Use firewall rules, implement authentication, restrict exports, use NFSv4 with Kerberos"
            }
        ])
    
    # Elasticsearch (Port 9200)
    elif port == 9200:
        vulnerabilities.extend([
            {
                "type": "Elasticsearch Exposed", 
                "severity": "High", 
                "description": "Elasticsearch accessible from network",
                "attack_vector": "Data theft, ransomware, unauthorized access",
                "remediation": "Use firewall rules, implement authentication, enable security features, restrict network access"
            }
        ])
    
    # MongoDB (Port 27017)
    elif port == 27017:
        vulnerabilities.extend([
            {
                "type": "MongoDB Exposed", 
                "severity": "High", 
                "description": "MongoDB accessible from network",
                "attack_vector": "Data theft, ransomware, unauthorized access",
                "remediation": "Use firewall rules, implement authentication, enable security features, restrict network access"
            }
        ])
    
    # Generic high-risk ports
    elif port < 1024:
        vulnerabilities.extend([
            {
                "type": "Privileged Port Service", 
                "severity": "Medium", 
                "description": "Service running on privileged port",
                "attack_vector": "Potential privilege escalation, targeted attacks",
                "remediation": "Ensure proper security configuration, regular updates, access controls"
            }
        ])
    
    # Generic unknown service
    else:
        vulnerabilities.extend([
            {
                "type": "Unknown Service", 
                "severity": "Medium", 
                "description": "Service running on non-standard port",
                "attack_vector": "Information gathering, potential vulnerabilities",
                "remediation": "Identify service, assess security, implement appropriate controls"
            }
        ])
    
    return vulnerabilities

def scan_ports_sync(target: str, ports: str, scan_type: str, timeout: int) -> Dict:
    """Synchronous port scanning function"""
    try:
        if nm:
            # Use nmap for comprehensive scanning
            # Map scan_type to proper nmap flags
            if scan_type.lower() == "tcp":
                scan_flag = "-sS"  # SYN scan for TCP
            elif scan_type.lower() == "udp":
                scan_flag = "-sU"  # UDP scan
            else:
                scan_flag = "-sS"  # Default to TCP SYN scan
            
            scan_args = f"{scan_flag} -p{ports} --host-timeout {timeout}s"
            nm.scan(target, arguments=scan_args)
            
            results = []
            if target in nm.all_hosts():
                for proto in nm[target].all_protocols():
                    ports_info = nm[target][proto]
                    for port, port_info in ports_info.items():
                        service = port_info.get('name', 'unknown')
                        state = port_info.get('state', 'unknown')
                        version = port_info.get('version', '')
                        
                        vulnerabilities = get_common_vulnerabilities(port, service)
                        
                        results.append({
                            "port": port,
                            "protocol": proto,
                            "state": state,
                            "service": service,
                            "version": version,
                            "vulnerabilities": vulnerabilities
                        })
            
            return {"success": True, "ports": results}
        else:
            # Fallback to basic socket scanning
            return basic_socket_scan(target, ports, timeout)
            
    except Exception as e:
        return {"success": False, "error": str(e)}

def basic_socket_scan(target: str, ports: str, timeout: int) -> Dict:
    """Basic socket-based port scanning fallback"""
    results = []
    
    # Parse port range
    if "-" in ports:
        start, end = map(int, ports.split("-"))
        port_list = range(start, end + 1)
    else:
        port_list = [int(p) for p in ports.split(",")]
    
    for port in port_list:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                service = "unknown"
                try:
                    service = socket.getservbyport(port)
                except:
                    pass
                
                vulnerabilities = get_common_vulnerabilities(port, service)
                
                results.append({
                    "port": port,
                    "protocol": "tcp",
                    "state": "open",
                    "service": service,
                    "version": "",
                    "vulnerabilities": vulnerabilities
                })
        except:
            continue
    
    return {"success": True, "ports": results}

def run_scan_background(scan_id: str, target: str, ports: str, scan_type: str, timeout: int):
    """Background task for running scans"""
    try:
        active_scans[scan_id] = True
        
        # Run the scan
        scan_data = scan_ports_sync(target, ports, scan_type, timeout)
        
        if scan_data["success"]:
            # Update scan result with completed data
            update_data = {
                "ports": scan_data["ports"],
                "status": "completed",
                "end_time": datetime.now().isoformat()
            }
            
            # Generate summary
            open_ports = len([p for p in scan_data["ports"] if p["state"] == "open"])
            total_vulnerabilities = sum(len(p.get("vulnerabilities", [])) for p in scan_data["ports"])
            
            update_data["summary"] = {
                "total_ports_scanned": len(scan_data["ports"]),
                "open_ports": open_ports,
                "closed_ports": len(scan_data["ports"]) - open_ports,
                "total_vulnerabilities": total_vulnerabilities,
                "scan_duration": "Completed"
            }
            
            # Update MongoDB with scan results
            try:
                asyncio.run(update_scan_result(scan_id, update_data))
                print(f"✅ Scan {scan_id} completed and saved to MongoDB")
            except Exception as update_error:
                print(f"❌ Failed to update scan {scan_id} in MongoDB: {update_error}")
            
        else:
            # Update scan result with failed status
            try:
                asyncio.run(update_scan_result(scan_id, {
                    "status": "failed",
                    "end_time": datetime.now().isoformat(),
                    "summary": {"error": scan_data.get("error", "Unknown error")}
                }))
                print(f"❌ Scan {scan_id} failed and status updated in MongoDB")
            except Exception as update_error:
                print(f"❌ Failed to update failed scan {scan_id} in MongoDB: {update_error}")
            
    except Exception as e:
        # Update scan result with error
        try:
            asyncio.run(update_scan_result(scan_id, {
                "status": "failed",
                "end_time": datetime.now().isoformat(),
                "summary": {"error": str(e)}
            }))
            print(f"❌ Scan {scan_id} error updated in MongoDB")
        except Exception as update_error:
            print(f"❌ Failed to update error scan {scan_id} in MongoDB: {update_error}")
    finally:
        active_scans[scan_id] = False

@app.post("/scan/ports", response_model=Dict)
async def start_port_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """Start a new port scan"""
    try:
        # Validate target
        if not request.target:
            raise HTTPException(status_code=400, detail="Target is required")
        
        # Validate scan_type
        if request.scan_type.lower() not in ["tcp", "udp"]:
            raise HTTPException(status_code=400, detail="Scan type must be 'tcp' or 'udp'")
        
        # Generate unique scan ID
        scan_id = str(uuid.uuid4())
        
        # Create scan result object
        scan_result = ScanResult(
            scan_id=scan_id,
            target=request.target,
            status="queued",
            start_time=datetime.now().isoformat()
        )
        
        # Save to MongoDB
        save_success = await save_scan_result(scan_result)
        if not save_success:
            raise HTTPException(status_code=500, detail="Failed to save scan to database")
        
        # Resolve port range if it's a predefined range
        actual_ports = request.ports
        if request.ports in WELL_KNOWN_PORTS:
            actual_ports = WELL_KNOWN_PORTS[request.ports]
        
        # Update status to scanning immediately
        update_success = await update_scan_result(scan_id, {"status": "scanning"})
        if not update_success:
            print(f"⚠️ Warning: Could not update scan {scan_id} status to scanning")
        
        # Start background scan
        background_tasks.add_task(
            run_scan_background,
            scan_id,
            request.target,
            actual_ports,
            request.scan_type,
            request.timeout
        )
        
        return {
            "scan_id": scan_id,
            "message": "Scan started successfully",
            "status": "queued"
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/scan/status/{scan_id}")
async def get_scan_status(scan_id: str):
    """Get the status of a scan"""
    scan = await get_scan_result(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "status": scan.get("status"),
        "target": scan.get("target"),
        "start_time": scan.get("start_time"),
        "end_time": scan.get("end_time"),
        "summary": scan.get("summary", {})
    }

@app.get("/scan/results/{scan_id}")
async def get_scan_results(scan_id: str):
    """Get the complete results of a scan"""
    scan = await get_scan_result(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    return {
        "scan_id": scan_id,
        "target": scan.get("target"),
        "status": scan.get("status"),
        "start_time": scan.get("start_time"),
        "end_time": scan.get("end_time"),
        "ports": scan.get("ports", []),
        "vulnerabilities": scan.get("vulnerabilities", []),
        "summary": scan.get("summary", {})
    }

@app.get("/scan/list")
async def list_scans():
    """List all scans"""
    if collection is None:
        raise HTTPException(status_code=500, detail="Database not connected")
    
    try:
        result = await list_all_scans()
        return result
    except Exception as e:
        print(f"Error in list_scans endpoint: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to list scans: {str(e)}")

@app.get("/scan/search")
async def search_scans(target: str = None, status: str = None, limit: int = 50):
    """Search scans by target, status, or other criteria"""
    if collection is None:
        raise HTTPException(status_code=500, detail="Database not connected")
    
    try:
        # Build search query
        query = {}
        if target:
            query["target"] = {"$regex": target, "$options": "i"}  # Case-insensitive search
        if status:
            query["status"] = status
        
        # Execute search
        cursor = collection.find(query, {
            "scan_id": 1,
            "target": 1,
            "status": 1,
            "start_time": 1,
            "end_time": 1,
            "created_at": 1,
            "summary": 1
        }).sort("created_at", -1).limit(limit)
        
    scans = []
        async for document in cursor:
            document.pop("_id", None)
            scans.append(document)
        
        return {
            "scans": scans,
            "total": len(scans),
            "query": query
        }
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Search failed: {str(e)}")

@app.delete("/scan/{scan_id}")
async def delete_scan(scan_id: str):
    """Delete a scan and its results"""
    # Check if scan exists
    scan = await get_scan_result(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
            # Delete from MongoDB
        success = await delete_scan_result(scan_id)
        if not success:
            raise HTTPException(status_code=500, detail="Failed to delete scan from database")
    
    # Remove from active scans if present
    if scan_id in active_scans:
        del active_scans[scan_id]
    
    return {"message": "Scan deleted successfully"}

@app.get("/port-ranges")
async def get_port_ranges():
    """Get available predefined port ranges"""
    return {
        "port_ranges": WELL_KNOWN_PORTS,
        "descriptions": {
            "common_services": "Most commonly used services (21 ports)",
            "web_services": "Web servers and development ports (8 ports)",
            "database_services": "Database servers (7 ports)",
            "mail_services": "Email services (7 ports)",
            "file_services": "File sharing and transfer (5 ports)",
            "remote_access": "Remote access and VNC (6 ports)",
            "gaming_services": "Popular gaming servers (12 ports)",
            "media_services": "Streaming and media servers (12 ports)"
        }
    }

@app.get("/security-recommendations")
async def get_security_recommendations():
    """Get comprehensive security recommendations and best practices"""
    return {
        "general_recommendations": {
            "network_security": [
                "Implement proper firewall rules and network segmentation",
                "Use VPN for remote access to sensitive services",
                "Regular network monitoring and intrusion detection",
                "Implement rate limiting and DDoS protection"
            ],
            "authentication": [
                "Use strong, unique passwords for all services",
                "Implement multi-factor authentication (2FA) where possible",
                "Use key-based authentication instead of passwords",
                "Regular credential rotation and access review"
            ],
            "encryption": [
                "Use encrypted protocols (SSH, SFTP, HTTPS) instead of plaintext",
                "Implement TLS 1.3 for web services",
                "Use strong encryption algorithms (AES-256, ChaCha20)",
                "Implement perfect forward secrecy"
            ],
            "access_control": [
                "Principle of least privilege - only necessary access",
                "Regular access reviews and privilege audits",
                "Implement role-based access control (RBAC)",
                "Monitor and log all access attempts"
            ]
        },
        "service_specific": {
            "web_services": [
                "Use HTTPS with valid SSL certificates",
                "Implement security headers (HSTS, CSP, X-Frame-Options)",
                "Regular security updates and patches",
                "Use Web Application Firewalls (WAF)",
                "Implement input validation and output encoding"
            ],
            "database_services": [
                "Never expose databases directly to the internet",
                "Use strong authentication and encryption",
                "Implement connection pooling and rate limiting",
                "Regular backups and disaster recovery testing",
                "Monitor for suspicious database activities"
            ],
            "file_services": [
                "Use encrypted file transfer protocols (SFTP, FTPS)",
                "Implement proper file permissions and ACLs",
                "Regular access audits and monitoring",
                "Use secure file sharing solutions",
                "Implement data loss prevention (DLP)"
            ],
            "remote_access": [
                "Use VPN for all remote access",
                "Implement strong authentication (2FA, certificates)",
                "Regular session monitoring and timeout",
                "Use secure protocols (SSH, RDP with encryption)",
                "Implement IP whitelisting where possible"
            ]
        },
        "monitoring_and_response": {
            "continuous_monitoring": [
                "Implement SIEM (Security Information and Event Management)",
                "Regular vulnerability assessments and penetration testing",
                "Monitor for unusual network traffic patterns",
                "Implement automated threat detection and response",
                "Regular security awareness training for staff"
            ],
            "incident_response": [
                "Develop and test incident response plans",
                "Establish clear escalation procedures",
                "Maintain incident response team contacts",
                "Regular incident response drills and training",
                "Document and learn from security incidents"
            ]
        }
    }

@app.get("/health")
async def health_check():
    """Health check endpoint"""
    mongodb_status = "connected" if collection is not None else "disconnected"
    return {
        "status": "healthy",
        "timestamp": datetime.now().isoformat(),
        "nmap_available": nm is not None,
        "mongodb_status": mongodb_status,
        "database_name": DATABASE_NAME if collection is not None else None,
        "collection_name": COLLECTION_NAME if collection is not None else None
    }

@app.post("/mongodb/connect")
async def manual_mongodb_connect():
    """Manually connect to MongoDB"""
    try:
        await connect_to_mongodb()
        if collection is not None:
            return {"message": "MongoDB connected successfully", "status": "connected"}
        else:
            return {"message": "Failed to connect to MongoDB", "status": "failed"}
    except Exception as e:
        return {"message": f"MongoDB connection failed: {str(e)}", "status": "error"}

@app.on_event("startup")
async def startup_event():
    """Initialize MongoDB connection on startup"""
    await connect_to_mongodb()

@app.on_event("shutdown")
async def shutdown_event():
    """Close MongoDB connection on shutdown"""
    await close_mongodb_connection()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
