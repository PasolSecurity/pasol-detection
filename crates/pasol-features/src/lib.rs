#![forbid(unsafe_code)]

use pasol_detection_sdk::{
    FEATURE_SCHEMA_VERSION, Feature, FeatureError, FeatureExtractor, FeatureReport,
    FeatureReportStatus, FeatureSource, FeatureState, ParserReport, evidence, feature, sort_report,
};
use serde_json::{Value, json};

const EXTRACTOR: &str = "pasol-features-pe";
const VERSION: &str = "0.1.0";

#[derive(Debug, Default, Clone, Copy)]
pub struct PeFeatureExtractor;

impl FeatureExtractor for PeFeatureExtractor {
    fn descriptor(&self) -> &'static str {
        EXTRACTOR
    }

    fn supports(&self, parser_name: &str, schema_version: &str, file_type: &str) -> bool {
        parser_name == "pasol-pe-parser"
            && schema_version.starts_with("1.")
            && matches!(file_type, "pe32" | "pe64" | "dotnet_pe32" | "dotnet_pe64")
    }

    fn extract(&self, report: &ParserReport) -> Result<FeatureReport, FeatureError> {
        if !self.supports(&report.parser, &report.schema_version, &report.file_type) {
            return Err(FeatureError::UnsupportedParser(report.parser.clone()));
        }
        let metadata = report.metadata.as_object().ok_or_else(|| {
            FeatureError::InvalidReport("parser metadata must be an object".to_owned())
        })?;
        let mut features = Vec::new();
        add_scalar(
            &mut features,
            "file.size.bytes",
            FeatureState::Present,
            Some(json!(report.size)),
            "/size",
            "Parser reported file size",
        );
        add_scalar(
            &mut features,
            "file.type",
            FeatureState::Present,
            Some(json!(report.file_type)),
            "/file_type",
            "Parser identified file type",
        );
        add_scalar(
            &mut features,
            "file.sha256.present",
            FeatureState::Present,
            Some(json!(true)),
            "/sha256",
            "Parser report contains SHA-256",
        );
        add_scalar(
            &mut features,
            "file.parser.partial",
            FeatureState::Present,
            Some(json!(report.status == "partial")),
            "/status",
            "Parser reported completion status",
        );
        add_scalar(
            &mut features,
            "file.parser.warning_count",
            FeatureState::Present,
            Some(json!(report.warnings.len())),
            "/warnings",
            "Parser warning count",
        );
        add_scalar(
            &mut features,
            "pe.machine.raw",
            FeatureState::Present,
            Some(path_value(metadata, "architecture.raw")?),
            "/metadata/architecture/raw",
            "PE machine value",
        );
        add_scalar(
            &mut features,
            "pe.architecture",
            FeatureState::Present,
            Some(path_value(metadata, "architecture.name")?),
            "/metadata/architecture/name",
            "PE architecture name",
        );
        add_scalar(
            &mut features,
            "pe.subsystem",
            FeatureState::Present,
            Some(path_value(metadata, "subsystem.name")?),
            "/metadata/subsystem/name",
            "PE subsystem name",
        );
        add_scalar(
            &mut features,
            "pe.entry_point.rva",
            FeatureState::Present,
            Some(path_value(metadata, "entry_point_rva")?),
            "/metadata/entry_point_rva",
            "PE entry point RVA",
        );
        add_scalar(
            &mut features,
            "pe.image_base",
            FeatureState::Present,
            Some(path_value(metadata, "image_base")?),
            "/metadata/image_base",
            "PE image base",
        );

        let sections = metadata.get("sections").and_then(Value::as_array);
        match sections {
            Some(sections) => {
                add_scalar(
                    &mut features,
                    "pe.sections.count",
                    FeatureState::Present,
                    Some(json!(sections.len())),
                    "/metadata/sections",
                    "PE section count",
                );
                let mut writable_exec = 0_u64;
                let mut writable = 0_u64;
                let mut executable = 0_u64;
                let mut max_entropy: Option<f64> = None;
                let mut high_entropy = 0_u64;
                let mut names = Vec::new();
                for (index, section) in sections.iter().enumerate() {
                    let permissions = section.get("permissions").and_then(Value::as_object);
                    let write = permissions
                        .and_then(|p| p.get("write"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    let execute = permissions
                        .and_then(|p| p.get("execute"))
                        .and_then(Value::as_bool)
                        .unwrap_or(false);
                    writable += u64::from(write);
                    executable += u64::from(execute);
                    writable_exec += u64::from(write && execute);
                    if let Some(entropy) = section.get("entropy").and_then(Value::as_f64) {
                        max_entropy =
                            Some(max_entropy.map_or(entropy, |current| current.max(entropy)));
                        if entropy >= 7.0 {
                            high_entropy += 1;
                        }
                    }
                    if let Some(name) = section.get("name").and_then(Value::as_str) {
                        names.push(name.to_owned());
                    }
                    let id = format!("pe.section.{index}.permissions.writable_executable");
                    add_scalar(
                        &mut features,
                        &id,
                        FeatureState::Present,
                        Some(json!(write && execute)),
                        &format!("/metadata/sections/{index}/permissions"),
                        "Section write and execute permissions",
                    );
                }
                add_scalar(
                    &mut features,
                    "pe.sections.writable.count",
                    FeatureState::Present,
                    Some(json!(writable)),
                    "/metadata/sections",
                    "Writable section count",
                );
                add_scalar(
                    &mut features,
                    "pe.sections.executable.count",
                    FeatureState::Present,
                    Some(json!(executable)),
                    "/metadata/sections",
                    "Executable section count",
                );
                add_scalar(
                    &mut features,
                    "pe.sections.writable_executable.count",
                    FeatureState::Present,
                    Some(json!(writable_exec)),
                    "/metadata/sections",
                    "Writable and executable section count",
                );
                add_scalar(
                    &mut features,
                    "pe.section.entropy.maximum",
                    max_entropy.map_or(FeatureState::Unknown, |_| FeatureState::Present),
                    max_entropy.map(|value| json!(value)),
                    "/metadata/sections",
                    "Maximum reported section entropy",
                );
                add_scalar(
                    &mut features,
                    "pe.section.entropy.high_count",
                    FeatureState::Present,
                    Some(json!(high_entropy)),
                    "/metadata/sections",
                    "Count of sections at or above entropy threshold 7.0",
                );
                add_scalar(
                    &mut features,
                    "pe.section.names",
                    FeatureState::Present,
                    Some(json!(names)),
                    "/metadata/sections",
                    "Reported section names",
                );
            }
            None => add_scalar(
                &mut features,
                "pe.sections.count",
                FeatureState::Unsupported,
                None,
                "/metadata/sections",
                "Parser did not provide section data",
            ),
        }

        add_collection_counts(
            &mut features,
            metadata,
            "imports",
            "pe.imports.dll_count",
            "pe.imports.symbol_count",
        );
        add_collection_counts(
            &mut features,
            metadata,
            "exports",
            "pe.exports.count",
            "pe.exports.named_count",
        );
        add_collection_counts(
            &mut features,
            metadata,
            "resources",
            "pe.resources.count",
            "pe.resources.count",
        );
        presence(
            &mut features,
            metadata,
            "debug",
            "pe.debug.present",
            "/metadata/debug",
        );
        presence(
            &mut features,
            metadata,
            "version_info",
            "pe.version.present",
            "/metadata/version_info",
        );
        nested_presence(
            &mut features,
            metadata,
            &["authenticode", "certificate_table_present"],
            "pe.certificate_table.present",
            "/metadata/authenticode/certificate_table_present",
        );
        nested_presence(
            &mut features,
            metadata,
            &["authenticode", "pkcs7_present"],
            "pe.certificate_table.pkcs7_present",
            "/metadata/authenticode/pkcs7_present",
        );

        let status = if report.status == "partial"
            || report.warnings.iter().any(|w| w.code.starts_with("limit."))
        {
            FeatureReportStatus::Partial
        } else {
            FeatureReportStatus::Complete
        };
        let mut result = FeatureReport {
            schema_version: FEATURE_SCHEMA_VERSION.to_owned(),
            extractor: EXTRACTOR.to_owned(),
            extractor_version: VERSION.to_owned(),
            source: FeatureSource {
                parser: report.parser.clone(),
                parser_version: report.parser_version.clone(),
                parser_schema_version: report.schema_version.clone(),
                sha256: report.sha256.clone(),
                file_type: report.file_type.clone(),
            },
            status,
            features,
            warnings: report
                .warnings
                .iter()
                .map(|warning| warning.message.clone())
                .collect(),
        };
        sort_report(&mut result);
        Ok(result)
    }
}

fn path_value(
    metadata: &serde_json::Map<String, Value>,
    path: &str,
) -> Result<Value, FeatureError> {
    let mut value = Value::Object(metadata.clone());
    for component in path.split('.') {
        value = value.get(component).cloned().ok_or_else(|| {
            FeatureError::InvalidReport(format!("missing required parser field: {path}"))
        })?;
    }
    Ok(value)
}

fn add_scalar(
    features: &mut Vec<Feature>,
    id: &str,
    state: FeatureState,
    value: Option<Value>,
    path: &str,
    summary: &str,
) {
    let mut item = feature(id, state, value);
    item.evidence.push(evidence(path, summary));
    features.push(item);
}

fn add_collection_counts(
    features: &mut Vec<Feature>,
    metadata: &serde_json::Map<String, Value>,
    key: &str,
    count_id: &str,
    secondary_id: &str,
) {
    let Some(items) = metadata.get(key).and_then(Value::as_array) else {
        add_scalar(
            features,
            count_id,
            FeatureState::Unsupported,
            None,
            &format!("/metadata/{key}"),
            "Parser did not provide collection data",
        );
        return;
    };
    add_scalar(
        features,
        count_id,
        FeatureState::Present,
        Some(json!(items.len())),
        &format!("/metadata/{key}"),
        "Parser collection count",
    );
    if secondary_id != count_id {
        let secondary = items
            .iter()
            .map(|item| {
                item.get("functions")
                    .and_then(Value::as_array)
                    .map_or(0, Vec::len)
            })
            .sum::<usize>();
        add_scalar(
            features,
            secondary_id,
            FeatureState::Present,
            Some(json!(secondary)),
            &format!("/metadata/{key}"),
            "Parser nested item count",
        );
    }
}

fn presence(
    features: &mut Vec<Feature>,
    metadata: &serde_json::Map<String, Value>,
    key: &str,
    id: &str,
    path: &str,
) {
    let Some(value) = metadata.get(key) else {
        add_scalar(
            features,
            id,
            FeatureState::Unsupported,
            None,
            path,
            "Parser did not provide this fact",
        );
        return;
    };
    let present = value.as_bool().unwrap_or(!value.is_null());
    add_scalar(
        features,
        id,
        FeatureState::Present,
        Some(json!(present)),
        path,
        "Parser reported structure presence",
    );
}

fn nested_presence(
    features: &mut Vec<Feature>,
    metadata: &serde_json::Map<String, Value>,
    keys: &[&str],
    id: &str,
    path: &str,
) {
    let value = keys
        .iter()
        .try_fold(Value::Object(metadata.clone()), |current, key| {
            current.get(*key).cloned()
        });
    let Some(value) = value else {
        add_scalar(
            features,
            id,
            FeatureState::Unsupported,
            None,
            path,
            "Parser did not provide this fact",
        );
        return;
    };
    add_scalar(
        features,
        id,
        FeatureState::Present,
        Some(json!(value.as_bool().unwrap_or(!value.is_null()))),
        path,
        "Parser reported structure presence",
    );
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn extraction_is_deterministic_and_preserves_partial_status() {
        let report = ParserReport {
            schema_version: "1.0.0".into(),
            parser: "pasol-pe-parser".into(),
            parser_version: "0.1.0".into(),
            file_type: "pe64".into(),
            sha256: "a".repeat(64),
            size: 12,
            status: "partial".into(),
            metadata: json!({"architecture":{"raw":34404,"name":"x86_64"},"subsystem":{"raw":3,"name":"windows_cui"},"entry_point_rva":"0x1000","image_base":"0x140000000","sections":[],"imports":[],"exports":[],"resources":[],"debug":[],"version_info":null,"authenticode":{"certificate_table_present":false,"pkcs7_present":false}}),
            warnings: vec![],
        };
        let extractor = PeFeatureExtractor;
        let left = serde_json::to_string(&extractor.extract(&report).expect("fixture is valid"))
            .expect("serializes");
        let right = serde_json::to_string(&extractor.extract(&report).expect("fixture is valid"))
            .expect("serializes");
        assert_eq!(left, right);
        assert!(left.contains("\"partial\""));
    }
}
