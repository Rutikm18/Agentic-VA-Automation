import enum


class UserRole(str, enum.Enum):
    admin = "admin"
    manager = "manager"
    tester = "tester"
    analyst = "analyst"
    auditor = "auditor"


class EngagementStatus(str, enum.Enum):
    draft = "draft"
    active = "active"
    paused = "paused"
    completed = "completed"


class AssetType(str, enum.Enum):
    server = "server"
    workstation = "workstation"
    network = "network"
    cloud = "cloud"
    container = "container"
    iot = "iot"


class AssetCriticality(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class FindingSeverity(str, enum.Enum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"
    info = "info"


class FindingStatus(str, enum.Enum):
    open = "open"
    confirmed = "confirmed"
    remediated = "remediated"
    accepted = "accepted"
    fp = "fp"


class DetectionStatus(str, enum.Enum):
    detected = "detected"
    missed = "missed"
    prevented = "prevented"
    unknown = "unknown"


class ScanJobType(str, enum.Enum):
    discovery = "discovery"
    vuln_scan = "vuln_scan"
    exploit = "exploit"
    ad_enum = "ad_enum"
    lateral = "lateral"
    cloud_scan = "cloud_scan"
    detection = "detection"
    ai_report = "ai_report"


class ScanJobStatus(str, enum.Enum):
    pending = "pending"
    running = "running"
    completed = "completed"
    failed = "failed"


class ReviewStatus(str, enum.Enum):
    pending = "pending"
    approved = "approved"
    rejected = "rejected"
