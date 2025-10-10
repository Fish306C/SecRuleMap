// src/models/ScanResult.js
const mongoose = require("mongoose");
const { Schema } = mongoose;

// Schema findings (có thể có nhiều loại khác nhau → để Mixed)
const FindingSchema = new Schema(
  {
    type: String,
    header: String,
    severity: String,
    detail: String,
    pattern: String, // cho sensitive_data_exposure
  },
  { _id: false, strict: false }
);

// Schema mỗi result (một URL)
const ResultSchema = new Schema(
  {
    url: String,
    status_code: Number,
    headers: { type: Schema.Types.Mixed }, // headers có thể thay đổi
    findings: { type: [Schema.Types.Mixed], default: [] }, // findings để Mixed cho chắc
  },
  { _id: false, strict: false }
);

// Schema cho rule_map.UNMAPPED
const RuleMapEntrySchema = new Schema(
  {
    url: String,
    evidence: String,
    finding_type: String,
    matched_by: String,
    rule: Schema.Types.Mixed, // có thể là object hoặc string
  },
  { _id: false, strict: false }
);

// Schema chính cho ScanResult
const ScanResultSchema = new Schema({
  scanId: { type: String, required: true, unique: true },
  scannername: String,
  start_url: { type: String, required: true },
  summary: { type: Schema.Types.Mixed }, // phòng trường hợp có thêm field khác ngoài scanned
  results: { type: [ResultSchema], default: [] },
  rule_map: {
    UNMAPPED: { type: [RuleMapEntrySchema], default: [] },
  },
  createdAt: { type: Date, default: () => new Date() },
});

module.exports = mongoose.model("scanResults", ScanResultSchema);
