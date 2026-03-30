const { query, validationResult } = require("express-validator");

exports.checkValidation = [
  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.engagementId = [
  query("engagementId")
    .notEmpty().withMessage("engagementId is required.")
    .isInt({ min: 1 }).withMessage("engagementId must be a positive integer."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.engagementType = [
  query("engagementId")
    .optional()
    .isInt({ min: 1 }).withMessage("engagementId must be a positive integer."),

  query("type")
    .optional()
    .isIn(["summary", "phases", "dashboard"])
    .withMessage("type must be one of: summary, phases, dashboard."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.endpointId = [
  query("endpointId")
    .notEmpty().withMessage("endpointId is required.")
    .isInt({ min: 1 }).withMessage("endpointId must be a positive integer."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.endpointType = [
  query("type")
    .optional()
    .isIn(["inbound", "inbound-summary", "outbound", "outbound-dependencies", "detail"])
    .withMessage("type must be one of: inbound, inbound-summary, outbound, outbound-dependencies, detail."),

  query("endpointId")
    .optional()
    .isInt({ min: 1 }).withMessage("endpointId must be a positive integer."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.endpointFilters = [
  query("classification")
    .optional()
    .isIn(["Valid", "Shadow", "New", "Rogue", "UNCLASSIFIED"])
    .withMessage("classification must be one of: Valid, Shadow, New, Rogue, UNCLASSIFIED."),

  query("riskBand")
    .optional()
    .isIn(["CRITICAL", "HIGH", "MEDIUM", "LOW"])
    .withMessage("riskBand must be one of: CRITICAL, HIGH, MEDIUM, LOW."),

  query("dataSensitivity")
    .optional()
    .isIn(["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])
    .withMessage("dataSensitivity must be one of: CRITICAL, HIGH, MEDIUM, LOW, UNKNOWN."),

  query("exposure")
    .optional()
    .isIn(["internal", "external", "partner"])
    .withMessage("exposure must be one of: internal, external, partner."),

  query("apiDirection")
    .optional()
    .isIn(["inbound", "outbound"])
    .withMessage("apiDirection must be one of: inbound, outbound."),

  query("pageNumber")
    .optional()
    .isInt({ min: 1 }).withMessage("pageNumber must be a positive integer."),

  query("pageSize")
    .optional()
    .isInt({ min: 1, max: 500 }).withMessage("pageSize must be between 1 and 500."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.owaspType = [
  query("type")
    .optional()
    .isIn(["conformance"])
    .withMessage("type must be: conformance."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];

exports.packageType = [
  query("type")
    .optional()
    .isIn(["bom"])
    .withMessage("type must be: bom."),

  (req, res, next) => {
    const errors = validationResult(req);
    if (!errors.isEmpty()) {
      const cleanErrors = errors.array().map(({ value, ...rest }) => rest);
      return res.status(422).json({
        message: "Validation error.",
        errors: cleanErrors,
      });
    }
    next();
  },
];