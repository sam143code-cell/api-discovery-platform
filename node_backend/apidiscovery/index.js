const jwtAuthMiddleware = require("../helper/jwtFile");
const router = require("express").Router({
  caseSensitive: true,
  strict: true,
});

const c = require("./apidiscoveryController");
const v = require("./validation");

router.get(
  "/engagement",
  jwtAuthMiddleware.checkValidUser,
  v.engagementType,
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    const { type, engagementId } = req.query;
    if (!engagementId)      return c.getEngagements(req, res, next);
    if (type === "summary")   return c.getEngagementSummary(req, res, next);
    if (type === "phases")    return c.getPhases(req, res, next);
    if (type === "dashboard") return c.getDashboard(req, res, next);
    return c.getEngagementById(req, res, next);
  }
);

router.get(
  "/endpoint",
  jwtAuthMiddleware.checkValidUser,
  [...v.engagementId, ...v.endpointType, ...v.endpointFilters],
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    req.params.endpointId = req.query.endpointId;
    const { type } = req.query;
    if (type === "inbound")                return c.getInbound(req, res, next);
    if (type === "inbound-summary")        return c.getInboundSummary(req, res, next);
    if (type === "outbound")               return c.getOutbound(req, res, next);
    if (type === "outbound-dependencies")  return c.getOutboundDependencies(req, res, next);
    if (type === "detail")                 return c.getEndpointById(req, res, next);
    return c.getEndpoints(req, res, next);
  }
);

router.get(
  "/owasp",
  jwtAuthMiddleware.checkValidUser,
  [...v.engagementId, ...v.owaspType],
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    const { type } = req.query;
    if (type === "conformance") return c.getOwaspConformance(req, res, next);
    return c.getOwasp(req, res, next);
  }
);

router.get(
  "/secret",
  jwtAuthMiddleware.checkValidUser,
  v.engagementId,
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    return c.getSecrets(req, res, next);
  }
);

router.get(
  "/shadow-rogue",
  jwtAuthMiddleware.checkValidUser,
  v.engagementId,
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    return c.getShadowRogue(req, res, next);
  }
);

router.get(
  "/package",
  jwtAuthMiddleware.checkValidUser,
  [...v.engagementId, ...v.packageType],
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    const { type } = req.query;
    if (type === "bom") return c.getBom(req, res, next);
    return c.getPackages(req, res, next);
  }
);

router.get(
  "/cve",
  jwtAuthMiddleware.checkValidUser,
  v.engagementId,
  (req, res, next) => {
    req.params.id = req.query.engagementId;
    return c.getCve(req, res, next);
  }
);

module.exports = { router };