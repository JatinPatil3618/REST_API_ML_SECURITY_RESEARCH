export const references = [
  "docs/ZAP_ATRDF_VERIFICATION.md",
  "docs/END_TO_END_VERIFICATION.md",
  "docs/RESEARCH_RESULTS.md",
  "docs/FEATURES.md",
  "docs/MODELS.md",
  "research/atrdf_payload_experiment/SIX_FAMILY_SCOPE.md",
  "research/atrdf_payload_experiment/XSS_RECALL_LIMIT.md",
  "research/atrdf_header_count_ablation/final_test_evaluation/FINAL_TEST_REPORT.md"
];

export const scopedValidation = {
  source: "research/atrdf_payload_experiment/SIX_FAMILY_SCOPE.md",
  kind: "Scoped validation on the existing seed-42 mask",
  rows: 21041,
  benign: 17271,
  attacks: 3770,
  tn: 17271,
  fp: 0,
  fn: 0,
  tp: 3770,
  accuracy: 1,
  precision: 1,
  recall: 1,
  f1: 1,
  fpr: 0,
  families: [
    ["SQL Injection", 956],
    ["Directory Traversal", 464],
    ["RCE", 488],
    ["Cookie Injection", 968],
    ["Log Forging", 459],
    ["LOG4J", 435]
  ]
};

export const frozenForest = {
  source: "research/atrdf_header_count_ablation/final_test_evaluation/FINAL_TEST_REPORT.md",
  metadata: "models/atrdf/model_metadata.json",
  kind: "One scoring pass of the frozen 13-feature forests. The six-family candidate was not scored.",
  rows: 36554,
  threshold: 0.5,
  accuracy: 0.9869,
  precision: 1,
  recall: 0.9389856362018558,
  metadataRecall: 0.9391,
  f1: 0.9685328438442375,
  metadataF1: 0.9686,
  rocAuc: 0.9796,
  fpr: 0,
  tn: 28687,
  fp: 0,
  fn: 480,
  tp: 7387,
  log4jRecall: 0.358768,
  log4jF1: 0.528079,
  log4jSupport: 747,
  logForgingRecall: 0.998761,
  misses: "479 LOG4J and 1 Log Forging",
  families: [
    ["Benign", "0.983543", "1.0", "0.991703", "28687"],
    ["Cookie Injection", "1.0", "1.0", "1.0", "1548"],
    ["Directory Traversal", "1.0", "1.0", "1.0", "788"],
    ["LOG4J", "1.0", "0.358768", "0.528079", "747"],
    ["Log Forging", "1.0", "0.998761", "0.999380", "807"],
    ["RCE", "1.0", "1.0", "1.0", "789"],
    ["SQL Injection", "1.0", "1.0", "1.0", "1585"],
    ["XSS", "1.0", "1.0", "1.0", "1603"]
  ]
};

export const bolaEvaluation = {
  source: "models/bola/model_metadata.json",
  replaySource: "docs/BOLA_MITIGATION_VERIFICATION.md",
  model: "bola_rf_behavioral",
  testRows: 4960,
  testSessions: 575,
  accuracy: 1,
  normalF1: 1,
  bolaF1: 1,
  rocAuc: 1,
  validationRows: 5030,
  validationNormal: 2469,
  validationBola: 2561,
  tn: 2469,
  fp: 0,
  fn: 0,
  tp: 2561,
  liveScores: [
    ["EXP-ZAP-PREVIEW", "REQ-1048", "Owner read of book 101", "BOLA 0.73 / NORMAL 0.27", "HTTP 200, gateway ALERT, backend allowed the owner"],
    ["EXP-ZAP-PREVIEW", "REQ-1049", "User02 cross-owner read", "BOLA 1.0", "HTTP 403, backend BOLA_AUTHORIZATION_DENIED"],
    ["EXP-BOLA-IDENTITY-8081", "REQ-1009", "User02 cross-owner update", "ALLOW, BOLA 0.45 / NORMAL 0.55", "HTTP 403, backend denied the write"],
    ["EXP-BOLA-IDENTITY-8081", "REQ-1010", "User02 cross-owner delete", "ALLOW, BOLA 0.44 / NORMAL 0.56", "HTTP 403, backend denied the delete"],
    ["EXP-ZAP-BOLA", "REQ-1081", "Anonymous public read of book 101", "BOLA model alert", "HTTP 200 public catalog read. Not a BOLA vulnerability."]
  ]
};

export const xssExclusion = {
  source: "research/atrdf_payload_experiment/XSS_RECALL_LIMIT.md",
  rows: 931,
  detected: 471,
  recall: 0.5059,
  payloadFree: 460,
  note: "XSS is outside the six-family class list. A laboratory script can be labeled RCE because of markup_script. That event is not an XSS detection."
};

export const activeRules = [
  ["ATRDF-SQL-STRUCTURE", "SQL-shaped text"],
  ["ATRDF-PATH-TRAVERSAL", "Dot-dot, encoded slash, or file-target path"],
  ["ATRDF-COMMAND-CHAIN", "Command-shaped text"],
  ["ATRDF-COOKIE-AUTHORITY", "Cookie authority text"],
  ["ATRDF-LOG-LINE", "Log line break or severity marker"],
  ["ATRDF-JNDI-LOOKUP", "JNDI lookup marker"],
  ["ATRDF-MARKUP-SCRIPT", "Markup or script-shaped text. Not an XSS class."]
];

export const historicalFamilies = [
  ["SQL Injection", "124", "REQ-1002", "ATRDF-SQL-STRUCTURE", "403"],
  ["Directory Traversal", "125", "REQ-1003", "ATRDF-PATH-TRAVERSAL", "403"],
  ["RCE marker", "126", "REQ-1004", "ATRDF-COMMAND-CHAIN", "403"],
  ["Cookie Injection", "127", "REQ-1005", "ATRDF-COOKIE-AUTHORITY", "401"],
  ["Log Forging", "128", "REQ-1006", "ATRDF-LOG-LINE", "403"],
  ["LOG4J", "129", "REQ-1007", "ATRDF-JNDI-LOOKUP", "403"]
];

export const historicalBola = [
  ["EXP-ZAP-PREVIEW", "170", "REQ-1048", "Owner management read, book 101", "HTTP 200", "ML BLOCK, BOLA 0.73, gateway ALERT, backend reached, title returned"],
  ["EXP-ZAP-PREVIEW", "171", "REQ-1049", "User02 cross-owner management read", "HTTP 403", "ML BLOCK, BOLA 1.0, gateway ALERT, BOLA_AUTHORIZATION_DENIED"],
  ["EXP-ZAP-BOLA", "17", "REQ-1075", "Owner management read, book 101", "HTTP 200", "ML BLOCK, BOLA 1.0, gateway ALERT, backend reached"],
  ["EXP-ZAP-BOLA", "18", "REQ-1076", "User02 cross-owner management read", "HTTP 403", "BOLA_AUTHORIZATION_DENIED, backend reached"],
  ["EXP-ZAP-BOLA", "20", "REQ-1078", "User02 edit of disposable book 111", "HTTP 403", "BOLA_PERMISSION_DENIED, title unchanged"],
  ["EXP-ZAP-BOLA", "21", "REQ-1079", "User02 delete of disposable book 111", "HTTP 403", "BOLA_PERMISSION_DENIED, book still present"],
  ["EXP-ZAP-BOLA", "22", "REQ-1080", "Management read with no token", "HTTP 401", "Authentication required. Please log in."],
  ["EXP-ZAP-BOLA", "23", "REQ-1081", "Anonymous public read of book 101", "HTTP 200", "Gateway ALERT + public catalog read. This is not a BOLA vulnerability."]
];

export const ruleOnlyExamples = [
  ["REQ-1151", "SQL-shaped text", "ML ALLOW, BENIGN, malicious probability 0.0", "ATRDF-SQL-STRUCTURE"],
  ["REQ-1109", "File-target text", "ML ALLOW, BENIGN, malicious probability 0.0", "ATRDF-PATH-TRAVERSAL"],
  ["REQ-1185", "Command-shaped text", "ML ALLOW, BENIGN, malicious probability 0.0", "ATRDF-COMMAND-CHAIN"]
];

export const modelComparison = {
  atrdfBinary: [
    ["Random Forest", "1.000000", "1.000000", "1.000000", "1.000000", "0.000000", "1.000000", "1.000000", "0.004883"],
    ["Gradient boosting", "1.000000", "1.000000", "1.000000", "1.000000", "0.000000", "1.000000", "1.000000", "0.003692"],
    ["Extra Trees", "1.000000", "1.000000", "1.000000", "1.000000", "0.000000", "1.000000", "1.000000", "0.003262"],
    ["Logistic regression", "1.000000", "1.000000", "1.000000", "1.000000", "0.000000", "1.000000", "1.000000", "0.000199"],
    ["Isolation Forest", "0.710718", "0.295276", "0.403682", "0.341073", "0.219372", "0.704291", "0.271399", "0.074370"]
  ],
  atrdfConfusion: [
    ["Random Forest, gradient boosting, Extra Trees, logistic regression", "15982", "0", "0", "3639"],
    ["Isolation Forest", "12476", "3506", "2170", "1469"]
  ],
  atrdfFamilies: [
    ["Benign", "1.000000", "1.000000", "1.000000", "15982"],
    ["Cookie Injection", "1.000000", "1.000000", "1.000000", "817"],
    ["Directory Traversal", "1.000000", "1.000000", "1.000000", "514"],
    ["LOG4J", "1.000000", "1.000000", "1.000000", "466"],
    ["Log Forging", "1.000000", "1.000000", "1.000000", "433"],
    ["RCE", "1.000000", "1.000000", "1.000000", "414"],
    ["SQL Injection", "1.000000", "1.000000", "1.000000", "995"]
  ],
  bolaBinary: [
    ["Random Forest", "0.971372", "1.000000", "0.943772", "0.971073", "0.000000", "0.994937", "0.995352", "0.008850"],
    ["Gradient boosting", "0.971372", "1.000000", "0.943772", "0.971073", "0.000000", "0.994908", "0.995338", "0.007171"],
    ["Extra Trees", "0.971372", "1.000000", "0.943772", "0.971073", "0.000000", "0.994886", "0.995312", "0.013580"],
    ["Logistic regression", "0.971372", "1.000000", "0.943772", "0.971073", "0.000000", "0.995580", "0.995905", "0.000128"],
    ["Isolation Forest", "0.667197", "0.620746", "0.890277", "0.731473", "0.564196", "0.784692", "0.771795", "0.065894"]
  ],
  bolaConfusion: [
    ["Four supervised models", "2469", "0", "144", "2417"],
    ["Isolation Forest", "1076", "1393", "281", "2280"]
  ],
  bolaLegitimate: [
    ["Four supervised models", "2469", "0.000000", "168", "0", "0.000000"],
    ["Isolation Forest", "2469", "0.564196", "168", "168", "1.000000"]
  ]
};

export const bolaFeatures = [
  "request_frequency", "unique_objects_recent", "object_switch", "unique_owners_recent",
  "owner_switch", "cross_owner_count_recent", "cross_owner_ratio_recent", "same_owner_ratio_recent",
  "same_object_repeat_ratio", "time_since_previous_request", "request_burst_rate", "hour",
  "session_length", "request_index"
];
