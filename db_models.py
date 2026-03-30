from sqlalchemy import Column, Integer, String, Text, Float, SmallInteger, DateTime, Enum, ForeignKey
from datetime import datetime
from database import Base


class Engagement(Base):
    __tablename__ = "Engagement"

    EngagementId          = Column(Integer, primary_key=True, autoincrement=True)
    EngagementName        = Column(String(255), nullable=False)
    ClientName            = Column(String(255), nullable=False)
    Mode                  = Column(Enum("passive", "active"), default="passive")
    ScanTargetEnvironment = Column(String(100))
    SchemaVersion         = Column(String(20))
    GeneratedAt           = Column(DateTime)
    StartedAt             = Column(DateTime)
    CompletedAt           = Column(DateTime)
    OverallRisk           = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), default="UNKNOWN")
    Narrative             = Column(Text)
    TotalApis             = Column(Integer, default=0)
    InboundApiCount       = Column(Integer, default=0)
    OutboundApiCount      = Column(Integer, default=0)
    OutboundExternalCount = Column(Integer, default=0)
    OutboundInternalCount = Column(Integer, default=0)
    ValidCount            = Column(Integer, default=0)
    ShadowCount           = Column(Integer, default=0)
    NewCount              = Column(Integer, default=0)
    RogueCount            = Column(Integer, default=0)
    UnclassifiedCount     = Column(Integer, default=0)
    SecretsCount          = Column(Integer, default=0)
    OWASPFindingsTotal    = Column(Integer, default=0)
    InferredOWASPFindings = Column(Integer, default=0)
    LiveOWASPFindings     = Column(Integer, default=0)
    CVEFindingsTotal      = Column(Integer, default=0)
    HighCriticalRiskCount = Column(Integer, default=0)
    EndpointsWithoutAuth  = Column(Integer, default=0)
    ExternalIntegrations  = Column(Integer, default=0)
    SensitivityCritical   = Column(Integer, default=0)
    SensitivityHigh       = Column(Integer, default=0)
    SensitivityMedium     = Column(Integer, default=0)
    SensitivityLow        = Column(Integer, default=0)
    SensitivityUnknown    = Column(Integer, default=0)
    TechStackRuntime      = Column(String(100))
    TechStackLanguage     = Column(String(100))
    TechStackFramework    = Column(String(100))
    TechStackFrontend     = Column(String(100))
    CreatedAt             = Column(DateTime, default=datetime.utcnow)
    UpdatedAt             = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive              = Column(SmallInteger, default=0)


class ApiEndpoint(Base):
    __tablename__ = "api_endpoints"

    EndpointId        = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId      = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    ApiDirection      = Column(Enum("inbound", "outbound"), default="inbound")
    EndpointUrl       = Column(Text, nullable=False)
    HttpMethod        = Column(String(20), default="UNKNOWN")
    Classification    = Column(Enum("Valid", "Shadow", "New", "Rogue", "UNCLASSIFIED"), default="UNCLASSIFIED")
    RiskScore         = Column(Integer, default=0)
    RiskBand          = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW"), default="LOW")
    AuthType          = Column(String(100))
    DataSensitivity   = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"), default="UNKNOWN")
    Exposure          = Column(String(50))
    Environment       = Column(String(100))
    FunctionalModule  = Column(String(200))
    FunctionalType    = Column(String(100))
    ApiVersion        = Column(String(20))
    TechStack         = Column(String(100))
    InferredOwner     = Column(String(200))
    Owner             = Column(String(200))
    BaselineStatus    = Column(String(100))
    StatusCode        = Column(Integer)
    ContentType       = Column(String(100))
    ResponseSizeBytes = Column(Integer)
    Remediation       = Column(Text)
    SourceFile        = Column(Text)
    FirstSeen         = Column(DateTime)
    LastSeen          = Column(DateTime)
    CreatedAt         = Column(DateTime, default=datetime.utcnow)
    UpdatedAt         = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive          = Column(SmallInteger, default=0)


class DiscoverySource(Base):
    __tablename__ = "discovery_source"

    SourceId     = Column(Integer, primary_key=True, autoincrement=True)
    EndpointId   = Column(Integer, ForeignKey("api_endpoints.EndpointId"), nullable=False)
    EngagementId = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    SourceName   = Column(String(100), nullable=False)
    CreatedAt    = Column(DateTime, default=datetime.utcnow)
    UpdatedAt    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=0)


class OWASPFinding(Base):
    __tablename__ = "owasp_findings"

    FindingId    = Column(Integer, primary_key=True, autoincrement=True)
    EndpointId   = Column(Integer, ForeignKey("api_endpoints.EndpointId"))
    EngagementId = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    Category     = Column(String(20))
    CategoryName = Column(String(200))
    Finding      = Column(Text)
    Severity     = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), default="INFO")
    Source       = Column(String(50))
    Remediation  = Column(Text)
    EndpointUrl  = Column(Text)
    CreatedAt    = Column(DateTime, default=datetime.utcnow)
    UpdatedAt    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=0)


class OWASPConformance(Base):
    __tablename__ = "owasp_conformance"

    ConformanceId    = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId     = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    OWASPId          = Column(String(10))
    Name             = Column(String(200))
    Status           = Column(String(50))
    AffectedCount    = Column(Integer, default=0)
    Note             = Column(Text)
    ConformanceLevel = Column(String(100))
    CreatedAt        = Column(DateTime, default=datetime.utcnow)
    UpdatedAt        = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive         = Column(SmallInteger, default=0)


class SecretFinding(Base):
    __tablename__ = "secret_findings"

    SecretId       = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    SecretType     = Column(String(100))
    FilePath       = Column(Text)
    LineNumber     = Column(Integer)
    Repo           = Column(Text)
    MatchPreview   = Column(String(200))
    Severity       = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW"), default="CRITICAL")
    Recommendation = Column(Text)
    CreatedAt      = Column(DateTime, default=datetime.utcnow)
    UpdatedAt      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=0)


class OutboundApi(Base):
    __tablename__ = "outbound_api"

    OutboundApiId  = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    Url            = Column(Text)
    Host           = Column(String(255))
    PathPrefix     = Column(String(255))
    HttpMethod     = Column(String(20), default="UNKNOWN")
    Integration    = Column(String(200))
    Category       = Column(String(100))
    Exposure       = Column(Enum("External", "Internal"), default="External")
    Risk           = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW"), default="MEDIUM")
    AuthMethod     = Column(String(100))
    SourceFiles    = Column(Text)
    LineNumber     = Column(Integer)
    Repo           = Column(Text)
    OWASPReference = Column(String(100))
    Recommendation = Column(Text)
    CreatedAt      = Column(DateTime, default=datetime.utcnow)
    UpdatedAt      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=0)


class OutboundDependency(Base):
    __tablename__ = "outbound_dependency"

    DependencyId   = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    Integration    = Column(String(200))
    Category       = Column(String(100))
    Exposure       = Column(Enum("External", "Internal"), default="External")
    Risk           = Column(Enum("CRITICAL", "HIGH", "MEDIUM", "LOW"), default="MEDIUM")
    Recommendation = Column(Text)
    CreatedAt      = Column(DateTime, default=datetime.utcnow)
    UpdatedAt      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=0)


class PackageDependency(Base):
    __tablename__ = "package_dependency"

    PackageId    = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    Name         = Column(String(255))
    Version      = Column(String(100))
    Type         = Column(String(100))
    Ecosystem    = Column(String(100))
    CreatedAt    = Column(DateTime, default=datetime.utcnow)
    UpdatedAt    = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = Column(SmallInteger, default=0)


class CVEFinding(Base):
    __tablename__ = "CVEFinding"

    CVEId         = Column(Integer, primary_key=True, autoincrement=True)
    EndpointId    = Column(Integer, ForeignKey("api_endpoints.EndpointId"))
    EngagementId  = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    CVENumber     = Column(String(50))
    Description   = Column(Text)
    Severity      = Column(String(50))
    CVSS          = Column(Float)
    EndpointCount = Column(Integer, default=0)
    CreatedAt     = Column(DateTime, default=datetime.utcnow)
    UpdatedAt     = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive      = Column(SmallInteger, default=0)


class ScanPhaseLog(Base):
    __tablename__ = "scan_phase_log"

    LogId          = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    PhaseNumber    = Column(Integer)
    PhaseName      = Column(String(100))
    Status         = Column(Enum("running", "completed", "skipped", "failed"), default="completed")
    StartedAt      = Column(DateTime)
    CompletedAt    = Column(DateTime)
    EndpointsFound = Column(Integer, default=0)
    Notes          = Column(Text)
    CreatedAt      = Column(DateTime, default=datetime.utcnow)
    UpdatedAt      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=0)


class ShadowRogueRegister(Base):
    __tablename__ = "shadow_rogue_register"

    RegistryId     = Column(Integer, primary_key=True, autoincrement=True)
    EngagementId   = Column(Integer, ForeignKey("Engagement.EngagementId"), nullable=False)
    EndpointId     = Column(Integer, ForeignKey("api_endpoints.EndpointId"), nullable=False)
    Classification = Column(Enum("Shadow", "Rogue"), nullable=False)
    RiskScore      = Column(Integer, default=0)
    ActionRequired = Column(Text)
    CreatedAt      = Column(DateTime, default=datetime.utcnow)
    UpdatedAt      = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = Column(SmallInteger, default=0)
