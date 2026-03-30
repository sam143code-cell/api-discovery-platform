from pydantic import BaseModel, Field
from typing import Optional, List
from enum import Enum


class ScanRequest(BaseModel):
    domain:        str                  = Field(...,  description="Target domain, e.g. http://10.20.40.14:7085")
    repo_url:      Optional[str]        = Field(None, description="Git repository URL")
    username:      Optional[str]        = Field(None, description="Git username")
    access_token:  Optional[str]        = Field(None, description="Git PAT or password")
    client_name:   Optional[str]        = Field("Client", description="Client label for reports")
    app_name:      Optional[str]        = Field(None, description="Application name for report narrative")
    pcap_files:    Optional[List[str]]  = Field(None, description="List of base64-encoded .pcap file contents")
    openapi_specs: Optional[List[str]]  = Field(None, description="List of base64-encoded OpenAPI/Swagger spec file contents")
    pcap_filenames:    Optional[List[str]] = Field(None, description="Original filenames for pcap_files (same order)")
    openapi_filenames: Optional[List[str]] = Field(None, description="Original filenames for openapi_specs (same order)")


class ScanStatus(str, Enum):
    queued  = "queued"
    running = "running"
    done    = "done"
    failed  = "failed"


class ScanAccepted(BaseModel):
    scan_id:    str
    status:     ScanStatus
    message:    str
    status_url: str


class ScanResult(BaseModel):
    scan_id:      str
    status:       ScanStatus
    started_at:   Optional[str]
    completed_at: Optional[str]
    error:        Optional[str]
    summary:      Optional[dict]
    output_files: Optional[dict]


class IngestRequest(BaseModel):
    engagement_name: Optional[str] = Field(None, description="Override engagement name stored in DB")