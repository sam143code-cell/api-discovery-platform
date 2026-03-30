const loggerObj = require("../../../core/logger.js");
const { QueryTypes } = require("sequelize");
const sequelizeDb = require("../../../core/mysql-db.js");
const t = require("../config/tableAlias");


const paginationFunc = async (pageNumber, pageSize) => {
  if (pageNumber === undefined || pageSize === undefined) {
    return { limit: Number(20), offset: Number(0) };
  }
  return {
    limit: Number(pageSize),
    offset: Number((pageNumber - 1) * pageSize),
  };
};

const buildEndpointWhere = (engagementId, query) => {
  const conditions = ["ae.EngagementId = :engagementId", "ae.IsActive = 0"];
  const replacements = { engagementId };

  if (query.classification) {
    conditions.push("ae.Classification = :classification");
    replacements.classification = query.classification;
  }
  if (query.riskBand) {
    conditions.push("ae.RiskBand = :riskBand");
    replacements.riskBand = query.riskBand;
  }
  if (query.dataSensitivity) {
    conditions.push("ae.DataSensitivity = :dataSensitivity");
    replacements.dataSensitivity = query.dataSensitivity;
  }
  if (query.exposure) {
    conditions.push("ae.Exposure = :exposure");
    replacements.exposure = query.exposure;
  }
  if (query.apiDirection) {
    conditions.push("ae.ApiDirection = :apiDirection");
    replacements.apiDirection = query.apiDirection;
  }

  return { conditions: conditions.join(" AND "), replacements };
};


exports.getEngagements = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT EngagementId, EngagementName, ClientName, Mode, ScanTargetEnvironment,
              OverallRisk, TotalApis, InboundApiCount, OutboundApiCount,
              ValidCount, ShadowCount, NewCount, RogueCount,
              SecretsCount, OWASPFindingsTotal, CVEFindingsTotal,
              HighCriticalRiskCount, StartedAt, CompletedAt, GeneratedAt
       FROM ${t.engagement}
       WHERE IsActive = 0
       ORDER BY CreatedAt DESC`,
      { type: QueryTypes.SELECT }
    );

    return res.status(200).json({
      success: true,
      message: "Engagement List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getEngagements",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getEngagementById = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT EngagementId, EngagementName, ClientName, Mode, ScanTargetEnvironment,
              SchemaVersion, GeneratedAt, StartedAt, CompletedAt,
              OverallRisk, Narrative, TotalApis, InboundApiCount, OutboundApiCount,
              OutboundExternalCount, OutboundInternalCount,
              ValidCount, ShadowCount, NewCount, RogueCount, UnclassifiedCount,
              SecretsCount, OWASPFindingsTotal, InferredOWASPFindings, LiveOWASPFindings,
              CVEFindingsTotal, HighCriticalRiskCount, EndpointsWithoutAuth,
              ExternalIntegrations, SensitivityCritical, SensitivityHigh,
              SensitivityMedium, SensitivityLow, SensitivityUnknown,
              TechStackRuntime, TechStackLanguage, TechStackFramework, TechStackFrontend
       FROM ${t.engagement}
       WHERE EngagementId = :id AND IsActive = 0`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Engagement not found" });
    }

    loggerObj.writeLogInfo("getEngagementById", "Engagement fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Engagement Details",
      payload: rows[0],
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getEngagementById",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getEngagementSummary = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT EngagementId, EngagementName, ClientName, OverallRisk, Narrative,
              TotalApis, InboundApiCount, OutboundApiCount, OutboundExternalCount,
              OutboundInternalCount, ValidCount, ShadowCount, NewCount, RogueCount,
              UnclassifiedCount, SecretsCount, OWASPFindingsTotal, InferredOWASPFindings,
              LiveOWASPFindings, CVEFindingsTotal, HighCriticalRiskCount,
              EndpointsWithoutAuth, ExternalIntegrations,
              SensitivityCritical, SensitivityHigh, SensitivityMedium,
              SensitivityLow, SensitivityUnknown
       FROM ${t.engagement}
       WHERE EngagementId = :id AND IsActive = 0`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    if (!rows.length) {
      return res.status(404).json({ error: "Engagement not found" });
    }

    loggerObj.writeLogInfo("getEngagementSummary", "Engagement summary fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Engagement Summary",
      payload: rows[0],
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getEngagementSummary",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getPhases = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT LogId, PhaseNumber, PhaseName, Status,
              StartedAt, CompletedAt, EndpointsFound, Notes
       FROM ${t.scanPhaseLog}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY PhaseNumber ASC`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Engagement Phases",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getPhases",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getDashboard = async (req, res, next) => {
  try {
    const id = req.params.id;

    const engRows = await sequelizeDb.query(
      `SELECT EngagementId, EngagementName, ClientName, OverallRisk,
              TotalApis, InboundApiCount, OutboundApiCount,
              OutboundExternalCount, OutboundInternalCount,
              ValidCount, ShadowCount, NewCount, RogueCount,
              SecretsCount, OWASPFindingsTotal, CVEFindingsTotal,
              HighCriticalRiskCount, EndpointsWithoutAuth,
              SensitivityCritical, SensitivityHigh, SensitivityMedium,
              SensitivityLow, SensitivityUnknown
       FROM ${t.engagement}
       WHERE EngagementId = :id AND IsActive = 0`,
      {
        replacements: { id },
        type: QueryTypes.SELECT,
      }
    );

    if (!engRows.length) {
      return res.status(404).json({ error: "Engagement not found" });
    }

    const eng = engRows[0];

    const byClassification = await sequelizeDb.query(
      `SELECT Classification, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND IsActive = 0
       GROUP BY Classification`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const byRiskBand = await sequelizeDb.query(
      `SELECT RiskBand, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND IsActive = 0
       GROUP BY RiskBand`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const byOwasp = await sequelizeDb.query(
      `SELECT Category, COUNT(FindingId) AS count
       FROM ${t.owaspFinding}
       WHERE EngagementId = :id AND IsActive = 0
       GROUP BY Category
       ORDER BY Category ASC`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const topRisk = await sequelizeDb.query(
      `SELECT EndpointId, EndpointUrl, HttpMethod, Classification,
              RiskScore, RiskBand, DataSensitivity, AuthType, InferredOwner
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY RiskScore DESC
       LIMIT 10`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const secretsBySeverity = await sequelizeDb.query(
      `SELECT Severity, COUNT(SecretId) AS count
       FROM ${t.secretFinding}
       WHERE EngagementId = :id AND IsActive = 0
       GROUP BY Severity`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    loggerObj.writeLogInfo("getDashboard", "Dashboard data fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Dashboard Data",
      payload: {
        engagement: eng,
        countsByClassification: byClassification,
        countsByRiskBand: byRiskBand,
        countsByOWASPCategory: byOwasp,
        inboundOutboundBreakdown: {
          inboundTotal: eng.InboundApiCount,
          outboundTotal: eng.OutboundApiCount,
          outboundExternal: eng.OutboundExternalCount,
          outboundInternal: eng.OutboundInternalCount,
        },
        dataSensitivityBreakdown: {
          CRITICAL: eng.SensitivityCritical,
          HIGH: eng.SensitivityHigh,
          MEDIUM: eng.SensitivityMedium,
          LOW: eng.SensitivityLow,
          UNKNOWN: eng.SensitivityUnknown,
        },
        top10RiskEndpoints: topRisk,
        secretsBySeverity,
      },
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getDashboard",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getEndpoints = async (req, res, next) => {
  try {
    const paginationData = await paginationFunc(req.query.pageNumber, req.query.pageSize);
    const { conditions, replacements } = buildEndpointWhere(req.params.id, req.query);

    const countResult = await sequelizeDb.query(
      `SELECT COUNT(ae.EndpointId) AS total
       FROM ${t.apiEndpoint} ae
       WHERE ${conditions}`,
      { replacements, type: QueryTypes.SELECT }
    );
    const total = countResult[0].total;

    const rows = await sequelizeDb.query(
      `SELECT ae.EndpointId, ae.ApiDirection, ae.EndpointUrl, ae.HttpMethod,
              ae.Classification, ae.RiskScore, ae.RiskBand, ae.AuthType,
              ae.DataSensitivity, ae.Exposure, ae.Environment,
              ae.FunctionalModule, ae.FunctionalType, ae.ApiVersion,
              ae.TechStack, ae.InferredOwner, ae.BaselineStatus,
              ae.StatusCode, ae.ContentType, ae.ResponseSizeBytes,
              ae.Remediation, ae.SourceFile, ae.FirstSeen, ae.LastSeen
       FROM ${t.apiEndpoint} ae
       WHERE ${conditions}
       ORDER BY ae.RiskScore DESC
       LIMIT :limit OFFSET :offset`,
      {
        replacements: { ...replacements, limit: paginationData.limit, offset: paginationData.offset },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Endpoint List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: total,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getEndpoints",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getInbound = async (req, res, next) => {
  try {
    const paginationData = await paginationFunc(req.query.pageNumber, req.query.pageSize);
    const { conditions, replacements } = buildEndpointWhere(req.params.id, {
      ...req.query,
      apiDirection: "inbound",
    });

    const countResult = await sequelizeDb.query(
      `SELECT COUNT(ae.EndpointId) AS total
       FROM ${t.apiEndpoint} ae
       WHERE ${conditions}`,
      { replacements, type: QueryTypes.SELECT }
    );
    const total = countResult[0].total;

    const rows = await sequelizeDb.query(
      `SELECT ae.EndpointId, ae.EndpointUrl, ae.HttpMethod, ae.Classification,
              ae.RiskScore, ae.RiskBand, ae.AuthType, ae.DataSensitivity,
              ae.Exposure, ae.Environment, ae.FunctionalModule, ae.FunctionalType,
              ae.ApiVersion, ae.TechStack, ae.InferredOwner, ae.BaselineStatus,
              ae.StatusCode, ae.Remediation, ae.SourceFile, ae.FirstSeen, ae.LastSeen
       FROM ${t.apiEndpoint} ae
       WHERE ${conditions}
       ORDER BY ae.RiskScore DESC
       LIMIT :limit OFFSET :offset`,
      {
        replacements: { ...replacements, limit: paginationData.limit, offset: paginationData.offset },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Inbound Endpoint List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: total,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getInbound",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getInboundSummary = async (req, res, next) => {
  try {
    const id = req.params.id;

    const byMethod = await sequelizeDb.query(
      `SELECT HttpMethod, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND ApiDirection = 'inbound' AND IsActive = 0
       GROUP BY HttpMethod`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const bySensitivity = await sequelizeDb.query(
      `SELECT DataSensitivity, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND ApiDirection = 'inbound' AND IsActive = 0
       GROUP BY DataSensitivity`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const byModule = await sequelizeDb.query(
      `SELECT FunctionalModule, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND ApiDirection = 'inbound' AND IsActive = 0
       GROUP BY FunctionalModule
       ORDER BY count DESC`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const byRisk = await sequelizeDb.query(
      `SELECT RiskBand, COUNT(EndpointId) AS count
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND ApiDirection = 'inbound' AND IsActive = 0
       GROUP BY RiskBand`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const totalRows = await sequelizeDb.query(
      `SELECT COUNT(EndpointId) AS total
       FROM ${t.apiEndpoint}
       WHERE EngagementId = :id AND ApiDirection = 'inbound' AND IsActive = 0`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    loggerObj.writeLogInfo("getInboundSummary", "Inbound summary fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Inbound Summary",
      payload: {
        total: totalRows[0].total,
        byMethod,
        bySensitivity,
        byModule,
        byRisk,
      },
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getInboundSummary",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getOutbound = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT OutboundApiId, Url, Host, PathPrefix, HttpMethod, Integration,
              Category, Exposure, Risk, AuthMethod, SourceFiles,
              LineNumber, Repo, OWASPReference, Recommendation
       FROM ${t.outboundApi}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY FIELD(Risk, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Outbound API List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getOutbound",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getOutboundDependencies = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT DependencyId, Integration, Category, Exposure, Risk, Recommendation
       FROM ${t.outboundDependency}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY FIELD(Risk, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Outbound Dependency List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getOutboundDependencies",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getEndpointById = async (req, res, next) => {
  try {
    const { id, endpointId } = req.params;

    const epRows = await sequelizeDb.query(
      `SELECT ae.EndpointId, ae.ApiDirection, ae.EndpointUrl, ae.HttpMethod,
              ae.Classification, ae.RiskScore, ae.RiskBand, ae.AuthType,
              ae.DataSensitivity, ae.Exposure, ae.Environment,
              ae.FunctionalModule, ae.FunctionalType, ae.ApiVersion,
              ae.TechStack, ae.InferredOwner, ae.Owner, ae.BaselineStatus,
              ae.StatusCode, ae.ContentType, ae.ResponseSizeBytes,
              ae.Remediation, ae.SourceFile, ae.FirstSeen, ae.LastSeen
       FROM ${t.apiEndpoint} ae
       WHERE ae.EndpointId = :endpointId AND ae.EngagementId = :id AND ae.IsActive = 0`,
      {
        replacements: { endpointId, id },
        type: QueryTypes.SELECT,
      }
    );

    if (!epRows.length) {
      return res.status(404).json({ error: "Endpoint not found" });
    }

    const owaspRows = await sequelizeDb.query(
      `SELECT FindingId, Category, CategoryName, Finding, Severity, Source, Remediation
       FROM ${t.owaspFinding}
       WHERE EndpointId = :endpointId AND IsActive = 0`,
      { replacements: { endpointId }, type: QueryTypes.SELECT }
    );

    const cveRows = await sequelizeDb.query(
      `SELECT CVEId, CVENumber, Description, Severity, CVSS
       FROM ${t.cveFinding}
       WHERE EndpointId = :endpointId AND IsActive = 0`,
      { replacements: { endpointId }, type: QueryTypes.SELECT }
    );

    const sourceRows = await sequelizeDb.query(
      `SELECT SourceId, SourceName
       FROM ${t.discoverySource}
       WHERE EndpointId = :endpointId AND IsActive = 0`,
      { replacements: { endpointId }, type: QueryTypes.SELECT }
    );

    loggerObj.writeLogInfo("getEndpointById", "Endpoint details fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Endpoint Details",
      payload: {
        ...epRows[0],
        owaspFindings: owaspRows,
        cveFindings: cveRows,
        discoverySources: sourceRows,
      },
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getEndpointById",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getOwasp = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT FindingId, EndpointId, Category, CategoryName,
              Finding, Severity, Source, Remediation, EndpointUrl
       FROM ${t.owaspFinding}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY FIELD(Severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    const grouped = rows.reduce((acc, row) => {
      const cat = row.Category || "UNKNOWN";
      if (!acc[cat]) acc[cat] = [];
      acc[cat].push(row);
      return acc;
    }, {});

    return res.status(200).json({
      success: true,
      message: "OWASP Findings",
      payload: { grouped, all: rows },
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getOwasp",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getOwaspConformance = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT ConformanceId, OWASPId, Name, Status,
              AffectedCount, Note, ConformanceLevel
       FROM ${t.owaspConformance}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY OWASPId ASC`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "OWASP Conformance",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getOwaspConformance",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getSecrets = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT SecretId, SecretType, FilePath, LineNumber,
              Repo, MatchPreview, Severity, Recommendation
       FROM ${t.secretFinding}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY FIELD(Severity, 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Secret Findings",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getSecrets",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getShadowRogue = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT sr.RegistryId, sr.Classification, sr.RiskScore, sr.ActionRequired,
              ae.EndpointUrl, ae.HttpMethod, ae.AuthType, ae.DataSensitivity,
              ae.Exposure, ae.FunctionalModule, ae.InferredOwner, ae.RiskBand
       FROM ${t.shadowRogueRegister} sr
       INNER JOIN ${t.apiEndpoint} ae
         ON ae.EndpointId = sr.EndpointId AND ae.IsActive = 0
       WHERE sr.EngagementId = :id AND sr.IsActive = 0
       ORDER BY sr.RiskScore DESC`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Shadow / Rogue API Register",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getShadowRogue",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getPackages = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT PackageId, Name, Version, Type, Ecosystem
       FROM ${t.packageDependency}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY Name ASC`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "Package Dependency List",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getPackages",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getBom = async (req, res, next) => {
  try {
    const id = req.params.id;

    const engRows = await sequelizeDb.query(
      `SELECT TechStackRuntime, TechStackLanguage, TechStackFramework, TechStackFrontend
       FROM ${t.engagement}
       WHERE EngagementId = :id AND IsActive = 0`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    if (!engRows.length) {
      return res.status(404).json({ error: "Engagement not found" });
    }

    const packages = await sequelizeDb.query(
      `SELECT PackageId, Name, Version, Type, Ecosystem
       FROM ${t.packageDependency}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY Name ASC`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const upstream = await sequelizeDb.query(
      `SELECT DependencyId, Integration, Category, Exposure, Risk, Recommendation
       FROM ${t.outboundDependency}
       WHERE EngagementId = :id AND IsActive = 0`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    const outboundApis = await sequelizeDb.query(
      `SELECT OutboundApiId, Url, Host, Integration, Category, Exposure, Risk, AuthMethod
       FROM ${t.outboundApi}
       WHERE EngagementId = :id AND IsActive = 0`,
      { replacements: { id }, type: QueryTypes.SELECT }
    );

    loggerObj.writeLogInfo("getBom", "Bill of Materials fetched successfully");

    return res.status(200).json({
      success: true,
      message: "Bill of Materials",
      payload: {
        techStack: {
          runtime: engRows[0].TechStackRuntime,
          language: engRows[0].TechStackLanguage,
          framework: engRows[0].TechStackFramework,
          frontend: engRows[0].TechStackFrontend,
        },
        packageDependencies: packages,
        upstreamDownstreamDependencies: upstream,
        outboundApis,
      },
      payloadCount: 1,
      totalCount: 1,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getBom",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};

exports.getCve = async (req, res, next) => {
  try {
    const rows = await sequelizeDb.query(
      `SELECT CVEId, EndpointId, CVENumber, Description, Severity, CVSS, EndpointCount
       FROM ${t.cveFinding}
       WHERE EngagementId = :id AND IsActive = 0
       ORDER BY CVSS DESC`,
      {
        replacements: { id: req.params.id },
        type: QueryTypes.SELECT,
      }
    );

    return res.status(200).json({
      success: true,
      message: "CVE Findings",
      payload: rows,
      payloadCount: rows.length,
      totalCount: rows.length,
    });
  } catch (error) {
    loggerObj.writeLogError(
      "getCve",
      error.message || "Unknown error",
      error.statusCode || 500,
      error.stack || "No stack trace available"
    );
    return res.status(500).json({ error: error.message || "Internal Server Error" });
  }
};