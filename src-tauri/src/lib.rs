pub mod cve_lookup;
pub mod models;
pub mod nmap_parser;
pub mod sample;
pub mod scoring;

use cve_lookup::CveEnrichment;
use models::{AuditProject, MatrixReport};
use nmap_parser::NmapImportResult;

/// Comando Tauri: devuelve una auditoría de ejemplo para iniciar rápido.
#[tauri::command]
fn get_sample_audit() -> AuditProject {
    sample::sample_audit()
}

/// Comando Tauri: calcula la matriz de impacto NxN y el ranking.
#[tauri::command]
fn calculate_impact_matrix(audit: AuditProject) -> MatrixReport {
    scoring::build_matrix_report(&audit)
}

/// Comando Tauri: genera el reporte ejecutivo en Markdown para documentación GRC.
#[tauri::command]
fn export_markdown_report(audit: AuditProject) -> String {
    scoring::render_markdown_report(&audit)
}

/// Comando Tauri: consulta NVD (NIST), FIRST EPSS y CISA KEV para enriquecer un CVE real.
#[tauri::command]
async fn lookup_cve(cve_id: String) -> Result<CveEnrichment, String> {
    cve_lookup::fetch_cve_enrichment(&cve_id).await
}

/// Comando Tauri: importa activos, puertos y CVEs desde un reporte Nmap XML (`nmap -oX`).
#[tauri::command]
fn import_nmap_xml(xml_content: String) -> Result<NmapImportResult, String> {
    nmap_parser::parse_nmap_xml(&xml_content)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .invoke_handler(tauri::generate_handler![
            get_sample_audit,
            calculate_impact_matrix,
            export_markdown_report,
            lookup_cve,
            import_nmap_xml
        ])
        .run(tauri::generate_context!())
        .expect("error al iniciar SecImpact");
}
