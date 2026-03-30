from . import db
from datetime import datetime


class Engagement(db.Model):
    __tablename__ = "Engagement"

    EngagementId          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementName        = db.Column(db.String(255), nullable=False)
    ClientName            = db.Column(db.String(255), nullable=False)
    Mode                  = db.Column(db.Enum("passive", "active"), default="passive")
    ScanTargetEnvironment = db.Column(db.String(100))
    SchemaVersion         = db.Column(db.String(20))
    GeneratedAt           = db.Column(db.DateTime)
    StartedAt             = db.Column(db.DateTime)
    CompletedAt           = db.Column(db.DateTime)
    OverallRisk           = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"), default="UNKNOWN")
    Narrative             = db.Column(db.Text)
    TotalApis             = db.Column(db.Integer, default=0)
    InboundApiCount       = db.Column(db.Integer, default=0)
    OutboundApiCount      = db.Column(db.Integer, default=0)
    OutboundExternalCount = db.Column(db.Integer, default=0)
    OutboundInternalCount = db.Column(db.Integer, default=0)
    ValidCount            = db.Column(db.Integer, default=0)
    ShadowCount           = db.Column(db.Integer, default=0)
    NewCount              = db.Column(db.Integer, default=0)
    RogueCount            = db.Column(db.Integer, default=0)
    UnclassifiedCount     = db.Column(db.Integer, default=0)
    SecretsCount          = db.Column(db.Integer, default=0)
    OWASPFindingsTotal    = db.Column(db.Integer, default=0)
    InferredOWASPFindings = db.Column(db.Integer, default=0)
    LiveOWASPFindings     = db.Column(db.Integer, default=0)
    CVEFindingsTotal      = db.Column(db.Integer, default=0)
    HighCriticalRiskCount = db.Column(db.Integer, default=0)
    EndpointsWithoutAuth  = db.Column(db.Integer, default=0)
    ExternalIntegrations  = db.Column(db.Integer, default=0)
    SensitivityCritical   = db.Column(db.Integer, default=0)
    SensitivityHigh       = db.Column(db.Integer, default=0)
    SensitivityMedium     = db.Column(db.Integer, default=0)
    SensitivityLow        = db.Column(db.Integer, default=0)
    SensitivityUnknown    = db.Column(db.Integer, default=0)
    TechStackRuntime      = db.Column(db.String(100))
    TechStackLanguage     = db.Column(db.String(100))
    TechStackFramework    = db.Column(db.String(100))
    TechStackFrontend     = db.Column(db.String(100))
    CreatedAt             = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt             = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive              = db.Column(db.SmallInteger, default=0)


class ApiEndpoint(db.Model):
    __tablename__ = "ApiEndpoint"

    EndpointId          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId        = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    ApiDirection        = db.Column(db.Enum("inbound", "outbound"), default="inbound")
    EndpointUrl         = db.Column(db.Text, nullable=False)
    HttpMethod          = db.Column(db.String(20), default="UNKNOWN")
    Classification      = db.Column(db.Enum("Valid","Shadow","New","Rogue","UNCLASSIFIED"), default="UNCLASSIFIED")
    RiskScore           = db.Column(db.Integer, default=0)
    RiskBand            = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW"), default="LOW")
    AuthType            = db.Column(db.String(100))
    DataSensitivity     = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW","UNKNOWN"), default="UNKNOWN")
    Exposure            = db.Column(db.String(50))
    Environment         = db.Column(db.String(100))
    FunctionalModule    = db.Column(db.String(200))
    FunctionalType      = db.Column(db.String(100))
    ApiVersion          = db.Column(db.String(20))
    TechStack           = db.Column(db.String(100))
    InferredOwner       = db.Column(db.String(200))
    Owner               = db.Column(db.String(200))
    BaselineStatus      = db.Column(db.String(100))
    StatusCode          = db.Column(db.Integer)
    ContentType         = db.Column(db.String(100))
    ResponseSizeBytes   = db.Column(db.Integer)
    Remediation         = db.Column(db.Text)
    SourceFile          = db.Column(db.Text)
    FirstSeen           = db.Column(db.DateTime)
    LastSeen            = db.Column(db.DateTime)
    CreatedAt           = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt           = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive            = db.Column(db.SmallInteger, default=0)


class DiscoverySource(db.Model):
    __tablename__ = "DiscoverySource"

    SourceId     = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EndpointId   = db.Column(db.Integer, db.ForeignKey("ApiEndpoint.EndpointId"), nullable=False)
    EngagementId = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    SourceName   = db.Column(db.String(100), nullable=False)
    CreatedAt    = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = db.Column(db.SmallInteger, default=0)


class OWASPFinding(db.Model):
    __tablename__ = "OWASPFinding"

    FindingId    = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EndpointId   = db.Column(db.Integer, db.ForeignKey("ApiEndpoint.EndpointId"))
    EngagementId = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    Category     = db.Column(db.String(20))
    CategoryName = db.Column(db.String(200))
    Finding      = db.Column(db.Text)
    Severity     = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW","INFO"), default="INFO")
    Source       = db.Column(db.String(50))
    Remediation  = db.Column(db.Text)
    EndpointUrl  = db.Column(db.Text)
    CreatedAt    = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = db.Column(db.SmallInteger, default=0)


class OWASPConformance(db.Model):
    __tablename__ = "OWASPConformance"

    ConformanceId    = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId     = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    OWASPId          = db.Column(db.String(10))
    Name             = db.Column(db.String(200))
    Status           = db.Column(db.String(50))
    AffectedCount    = db.Column(db.Integer, default=0)
    Note             = db.Column(db.Text)
    ConformanceLevel = db.Column(db.String(100))
    CreatedAt        = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt        = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive         = db.Column(db.SmallInteger, default=0)


class SecretFinding(db.Model):
    __tablename__ = "SecretFinding"

    SecretId       = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId   = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    SecretType     = db.Column(db.String(100))
    FilePath       = db.Column(db.Text)
    LineNumber     = db.Column(db.Integer)
    Repo           = db.Column(db.Text)
    MatchPreview   = db.Column(db.String(200))
    Severity       = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW"), default="CRITICAL")
    Recommendation = db.Column(db.Text)
    CreatedAt      = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = db.Column(db.SmallInteger, default=0)


class OutboundApi(db.Model):
    __tablename__ = "OutboundApi"

    OutboundApiId  = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId   = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    Url            = db.Column(db.Text)
    Host           = db.Column(db.String(255))
    PathPrefix     = db.Column(db.String(255))
    HttpMethod     = db.Column(db.String(20), default="UNKNOWN")
    Integration    = db.Column(db.String(200))
    Category       = db.Column(db.String(100))
    Exposure       = db.Column(db.Enum("External","Internal"), default="External")
    Risk           = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW"), default="MEDIUM")
    AuthMethod     = db.Column(db.String(100))
    SourceFiles    = db.Column(db.Text)
    LineNumber     = db.Column(db.Integer)
    Repo           = db.Column(db.Text)
    OWASPReference = db.Column(db.String(100))
    Recommendation = db.Column(db.Text)
    CreatedAt      = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = db.Column(db.SmallInteger, default=0)


class OutboundDependency(db.Model):
    __tablename__ = "OutboundDependency"

    DependencyId   = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId   = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    Integration    = db.Column(db.String(200))
    Category       = db.Column(db.String(100))
    Exposure       = db.Column(db.Enum("External","Internal"), default="External")
    Risk           = db.Column(db.Enum("CRITICAL","HIGH","MEDIUM","LOW"), default="MEDIUM")
    Recommendation = db.Column(db.Text)
    CreatedAt      = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = db.Column(db.SmallInteger, default=0)


class PackageDependency(db.Model):
    __tablename__ = "PackageDependency"

    PackageId    = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    Name         = db.Column(db.String(255))
    Version      = db.Column(db.String(100))
    Type         = db.Column(db.String(100))
    Ecosystem    = db.Column(db.String(100))
    CreatedAt    = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt    = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive     = db.Column(db.SmallInteger, default=0)


class CVEFinding(db.Model):
    __tablename__ = "CVEFinding"

    CVEId         = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EndpointId    = db.Column(db.Integer, db.ForeignKey("ApiEndpoint.EndpointId"))
    EngagementId  = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    CVENumber     = db.Column(db.String(50))
    Description   = db.Column(db.Text)
    Severity      = db.Column(db.String(50))
    CVSS          = db.Column(db.Float)
    EndpointCount = db.Column(db.Integer, default=0)
    CreatedAt     = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt     = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive      = db.Column(db.SmallInteger, default=0)


class ScanPhaseLog(db.Model):
    __tablename__ = "ScanPhaseLog"

    LogId          = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId   = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    PhaseNumber    = db.Column(db.Integer)
    PhaseName      = db.Column(db.String(100))
    Status         = db.Column(db.Enum("running","completed","skipped","failed"), default="completed")
    StartedAt      = db.Column(db.DateTime)
    CompletedAt    = db.Column(db.DateTime)
    EndpointsFound = db.Column(db.Integer, default=0)
    Notes          = db.Column(db.Text)
    CreatedAt      = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = db.Column(db.SmallInteger, default=0)


class ShadowRogueRegister(db.Model):
    __tablename__ = "ShadowRogueRegister"

    RegistryId     = db.Column(db.Integer, primary_key=True, autoincrement=True)
    EngagementId   = db.Column(db.Integer, db.ForeignKey("Engagement.EngagementId"), nullable=False)
    EndpointId     = db.Column(db.Integer, db.ForeignKey("ApiEndpoint.EndpointId"), nullable=False)
    Classification = db.Column(db.Enum("Shadow","Rogue"), nullable=False)
    RiskScore      = db.Column(db.Integer, default=0)
    ActionRequired = db.Column(db.Text)
    CreatedAt      = db.Column(db.DateTime, default=datetime.utcnow)
    UpdatedAt      = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    IsActive       = db.Column(db.SmallInteger, default=0)