use serde::{Deserialize, Serialize};

/// Nivel de exposición del activo en la red.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Exposure {
    Internet,
    Dmz,
    Internal,
}

/// Tipo de activo dentro de la infraestructura auditada.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AssetType {
    WebApp,
    Database,
    Server,
    ActiveDirectory,
    Network,
    Cloud,
    Workstation,
}

/// Estado de remediación de una vulnerabilidad.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum FindingStatus {
    Open,
    Mitigated,
    Accepted,
}

/// Nivel cualitativo final del riesgo en la matriz.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

/// Marco de Gobernanza / GRC o AppSec seleccionable globalmente.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GrcFramework {
    Iso27001,
    NistCsf,
    CisControls,
    OwaspTop10,
}

/// Ajuste manual hecho por el auditor para un par (CVE + Activo).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskOverride {
    pub impact: u8,
    pub likelihood: u8,
    pub note: String,
    #[serde(default)]
    pub custom_grc_control: Option<String>,
}

/// Activo de la infraestructura (servidor, DB, aplicación, etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Asset {
    pub id: String,
    pub name: String,
    pub host: String,
    pub asset_type: AssetType,
    pub exposure: Exposure,
    /// Criticidad de negocio de 1 (baja) a 5 (crítica).
    pub criticality: u8,
    pub owner: String,
}

/// Hallazgo o vulnerabilidad (CVE) encontrada en la auditoría.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Finding {
    pub id: String,
    pub cve_id: String,
    pub title: String,
    pub description: String,
    /// Puntuación CVSS v3/v4 (0.0 a 10.0).
    pub cvss: f64,
    /// Probabilidad EPSS en porcentaje (0.0 a 100.0).
    pub epss: f64,
    /// Indica si está en el catálogo CISA KEV (explotada activamente).
    pub in_kev: bool,
    pub status: FindingStatus,
    /// IDs de los activos afectados por este CVE.
    pub asset_ids: Vec<String>,
    pub remediation: String,
    /// Identificador CWE opcional (ej. CWE-78, CWE-89) para mapeo GRC preciso.
    #[serde(default)]
    pub cwe: String,
}

/// Configuración metodológica de la matriz y marco GRC.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditConfig {
    /// Escala de la matriz: 3 (3x3), 4 (4x4) o 5 (5x5).
    pub matrix_size: u8,
    pub framework: GrcFramework,
}

/// Proyecto completo de auditoría.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuditProject {
    pub name: String,
    pub client: String,
    pub auditor: String,
    pub date: String,
    pub config: AuditConfig,
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    /// Mapa de key "findingId__assetId" -> criterio manual del auditor.
    #[serde(default)]
    pub overrides: std::collections::HashMap<String, RiskOverride>,
    /// IDs de RiskItem marcados para simular "Riesgo Residual" (What-If).
    #[serde(default)]
    pub planned_remediation_ids: Vec<String>,
}

/// Resultado de evaluar un par (Hallazgo + Activo) dentro de la matriz.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RiskItem {
    pub id: String,
    pub finding_id: String,
    pub cve_id: String,
    pub title: String,
    pub asset_id: String,
    pub asset_name: String,
    pub asset_host: String,
    pub asset_type: AssetType,
    pub exposure: Exposure,
    pub asset_criticality: u8,
    pub cvss: f64,
    pub epss: f64,
    pub in_kev: bool,
    pub status: FindingStatus,
    /// Valores sugeridos automáticamente por el motor Rust.
    pub suggested_impact: u8,
    pub suggested_likelihood: u8,
    pub suggestion_reason: String,
    /// Valores efectivos (sugeridos o calibrados por el auditor).
    pub impact: u8,
    pub likelihood: u8,
    pub is_calibrated: bool,
    pub auditor_note: String,
    /// Impacto x Probabilidad (1..=N*N).
    pub risk_score: u8,
    pub max_score: u8,
    pub risk_level: RiskLevel,
    pub sla_window: String,
    pub grc_control: String,
    pub remediation: String,
    pub in_remediation_plan: bool,
}

/// Celda individual del Heatmap NxN.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixCell {
    pub impact: u8,
    pub likelihood: u8,
    pub score: u8,
    pub level: RiskLevel,
    pub count: usize,
    pub item_ids: Vec<String>,
}

/// Métricas ejecutivas (KPIs) + comparativa Riesgo Actual vs. Riesgo Residual.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixSummary {
    pub matrix_size: u8,
    pub max_score: u8,
    pub total_assets: usize,
    pub total_findings: usize,
    pub open_risk_pairs: usize,
    pub critical_count: usize,
    pub high_count: usize,
    pub medium_count: usize,
    pub low_count: usize,
    pub kev_count: usize,
    pub calibrated_count: usize,
    pub current_avg_score: f64,
    /// Métricas simuladas tras aplicar los ítems en `planned_remediation_ids`.
    pub residual_open_pairs: usize,
    pub residual_critical_count: usize,
    pub residual_high_count: usize,
    pub residual_avg_score: f64,
    pub risk_reduction_pct: f64,
}

/// Respuesta completa que devuelve Rust al frontend.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MatrixReport {
    pub summary: MatrixSummary,
    pub cells: Vec<MatrixCell>,
    pub items: Vec<RiskItem>,
}
