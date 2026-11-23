use std::collections::{HashMap, HashSet};

use crate::models::{
    Asset, AssetType, AuditProject, Exposure, Finding, FindingStatus, GrcFramework, MatrixCell,
    MatrixReport, MatrixSummary, RiskItem, RiskLevel,
};

/// Plazo sugerido de remediación (SLA) según el nivel de riesgo.
pub fn sla_window_for_level(level: &RiskLevel) -> String {
    match level {
        RiskLevel::Critical => "Inmediato (24–72h)".into(),
        RiskLevel::High => "Corto plazo (7–15 días)".into(),
        RiskLevel::Medium => "Mediano plazo (30 días)".into(),
        RiskLevel::Low => "Mantenimiento (90 días)".into(),
    }
}

/// Normaliza la escala de matriz permitida (3, 4 o 5).
pub fn normalize_matrix_size(size: u8) -> u8 {
    match size {
        3 => 3,
        4 => 4,
        _ => 5,
    }
}

/// Clasifica el puntaje según el porcentaje sobre el máximo de la matriz (N*N).
pub fn classify_risk_level(score: u8, matrix_size: u8) -> RiskLevel {
    let max_score = (matrix_size * matrix_size) as f64;
    let ratio = (score as f64) / max_score;
    if ratio >= 0.64 {
        RiskLevel::Critical
    } else if ratio >= 0.38 {
        RiskLevel::High
    } else if ratio >= 0.19 {
        RiskLevel::Medium
    } else {
        RiskLevel::Low
    }
}

/// Escala un valor en [1.0..=5.0] a la escala seleccionada (1..=N).
fn scale_to_matrix(value_1_to_5: f64, matrix_size: u8) -> u8 {
    let clamped = value_1_to_5.clamp(1.0, 5.0);
    let normalized = (clamped - 1.0) / 4.0;
    let scaled = 1.0 + normalized * ((matrix_size - 1) as f64);
    scaled.round().clamp(1.0, matrix_size as f64) as u8
}

/// Calcula el Eje Y sugerido: Impacto (1..=N).
pub fn compute_suggested_impact(asset: &Asset, finding: &Finding, matrix_size: u8) -> u8 {
    let crit = asset.criticality.clamp(1, 5) as f64;
    let cvss_scaled = ((finding.cvss.clamp(0.0, 10.0) / 10.0) * 4.0) + 1.0;
    let raw_5 = (crit * 0.65) + (cvss_scaled * 0.35);
    scale_to_matrix(raw_5, matrix_size)
}

/// Calcula el Eje X sugerido: Probabilidad (1..=N).
pub fn compute_suggested_likelihood(asset: &Asset, finding: &Finding, matrix_size: u8) -> u8 {
    let epss = finding.epss.clamp(0.0, 100.0);

    let mut score_5: f64 = if epss >= 70.0 {
        5.0
    } else if epss >= 40.0 {
        4.0
    } else if epss >= 15.0 {
        3.0
    } else if epss >= 3.0 {
        2.0
    } else {
        1.0
    };

    if finding.in_kev {
        score_5 = score_5.max(4.0) + 1.0;
    }

    match asset.exposure {
        Exposure::Internet => score_5 += 0.8,
        Exposure::Dmz => score_5 += 0.3,
        Exposure::Internal => score_5 -= 0.4,
    }

    scale_to_matrix(score_5, matrix_size)
}

/// Explica en lenguaje claro por qué Rust sugirió esos ejes.
fn build_suggestion_reason(asset: &Asset, finding: &Finding) -> String {
    let exp = match asset.exposure {
        Exposure::Internet => "expuesto a Internet",
        Exposure::Dmz => "ubicado en DMZ",
        Exposure::Internal => "en red interna",
    };
    let kev_part = if finding.in_kev {
        " + explotación activa (CISA KEV)"
    } else {
        ""
    };
    format!(
        "Criticidad {}/5 ({}) · CVSS {:.1} · EPSS {:.1}%{}",
        asset.criticality, exp, finding.cvss, finding.epss, kev_part
    )
}

/// Clasifica la categoría técnica del hallazgo según CWE, título, descripción y tipo de activo.
enum VulnCategory {
    AuthAndPrivilege,
    RemoteCodeExec,
    BackdoorAndSupplyChain,
    DenialOfService,
    DatabaseAndData,
    NetworkPerimeter,
    WebAndApi,
    MemoryAndLibraries,
    GeneralVuln,
}

fn detect_vuln_category(asset: &Asset, finding: &Finding) -> VulnCategory {
    let text = format!(
        "{} {} {} {}",
        finding.cve_id, finding.cwe, finding.title, finding.description
    )
    .to_lowercase();

    if text.contains("backdoor")
        || text.contains("malicious")
        || text.contains("trojan")
        || text.contains("supply chain")
        || text.contains("vsftpd")
        || text.contains("cwe-506")
        || text.contains("cwe-912")
    {
        VulnCategory::BackdoorAndSupplyChain
    } else if text.contains("denial of service")
        || text.contains("denegación de servicio")
        || text.contains(" dos ")
        || text.contains("range header")
        || text.contains("resource consumption")
        || text.contains("exhaustion")
        || text.contains("cwe-400")
        || text.contains("cwe-770")
    {
        VulnCategory::DenialOfService
    } else if text.contains("rce")
        || text.contains("command injection")
        || text.contains("shell metacharacters")
        || text.contains("arbitrary commands")
        || text.contains("execute arbitrary")
        || text.contains("log4j")
        || text.contains("log4shell")
        || text.contains("jndi")
        || text.contains("deserializ")
        || text.contains("ejecución remota")
        || text.contains("cwe-78")
        || text.contains("cwe-77")
        || text.contains("cwe-94")
        || text.contains("cwe-502")
    {
        VulnCategory::RemoteCodeExec
    } else if text.contains("ntlm")
        || text.contains("kerberos")
        || text.contains("privilege")
        || text.contains("privilegio")
        || text.contains("authentication")
        || text.contains("autenticación")
        || text.contains("bypass")
        || text.contains("credencial")
        || text.contains("cwe-287")
        || text.contains("cwe-269")
        || text.contains("cwe-306")
        || asset.asset_type == AssetType::ActiveDirectory
    {
        VulnCategory::AuthAndPrivilege
    } else if text.contains("sql")
        || text.contains("database")
        || text.contains("base de datos")
        || text.contains("postgres")
        || text.contains("mysql")
        || text.contains("cwe-89")
        || asset.asset_type == AssetType::Database
    {
        VulnCategory::DatabaseAndData
    } else if text.contains("vpn")
        || text.contains("ssh")
        || text.contains("smb")
        || text.contains("samba")
        || text.contains("firewall")
        || text.contains("gateway")
        || text.contains("perimetral")
        || asset.asset_type == AssetType::Network
    {
        VulnCategory::NetworkPerimeter
    } else if text.contains("xss")
        || text.contains("csrf")
        || text.contains("ssrf")
        || text.contains("cross-site")
        || text.contains("http")
        || text.contains("apache")
        || text.contains("nginx")
        || text.contains("api")
        || text.contains("cwe-79")
        || text.contains("cwe-352")
        || text.contains("cwe-918")
        || asset.asset_type == AssetType::WebApp
    {
        VulnCategory::WebAndApi
    } else if text.contains("buffer overflow")
        || text.contains("heap")
        || text.contains("libcurl")
        || text.contains("openssl")
        || text.contains("memory")
        || text.contains("memoria")
        || text.contains("cwe-119")
        || text.contains("cwe-120")
        || text.contains("cwe-787")
    {
        VulnCategory::MemoryAndLibraries
    } else {
        VulnCategory::GeneralVuln
    }
}

/// Sugiere el control GRC correspondiente según el marco seleccionado y categoría real del hallazgo.
pub fn map_grc_control(framework: &GrcFramework, asset: &Asset, finding: &Finding) -> String {
    let cat = detect_vuln_category(asset, finding);
    match framework {
        GrcFramework::CisControls => match cat {
            VulnCategory::BackdoorAndSupplyChain => "CIS v8 · 2.5 / 10.1 (Software Autorizado y Defensa Antimalware)".into(),
            VulnCategory::DenialOfService => "CIS v8 · 4.1 / 13.6 (Configuración Segura y Protección de Red)".into(),
            VulnCategory::AuthAndPrivilege => "CIS v8 · 5.2 / 6.3 (Gestión de Cuentas y Control de Acceso)".into(),
            VulnCategory::RemoteCodeExec => "CIS v8 · 7.4 / 16.11 (Remediación Crítica y Código Seguro)".into(),
            VulnCategory::DatabaseAndData => "CIS v8 · 3.3 / 3.11 (Protección de Datos y Mínimo Privilegio)".into(),
            VulnCategory::NetworkPerimeter => "CIS v8 · 12.2 / 13.6 (Infraestructura Segura y Segmentación)".into(),
            VulnCategory::WebAndApi => "CIS v8 · 16.1 / 16.12 (Seguridad de Aplicaciones Web/API)".into(),
            VulnCategory::MemoryAndLibraries => "CIS v8 · 2.2 / 7.4 (Inventario de Librerías y Parcheo)".into(),
            VulnCategory::GeneralVuln => "CIS v8 · 7.4 (Gestión Continua de Vulnerabilidades)".into(),
        },
        GrcFramework::Iso27001 => match cat {
            VulnCategory::BackdoorAndSupplyChain => "ISO 27001:2022 · A.8.7 / A.8.19 (Protección contra Malware e Integridad)".into(),
            VulnCategory::DenialOfService => "ISO 27001:2022 · A.8.6 / A.8.20 (Capacidad y Disponibilidad de Red)".into(),
            VulnCategory::AuthAndPrivilege => "ISO 27001:2022 · A.5.15 / A.8.2 (Control de Acceso y Privilegios)".into(),
            VulnCategory::RemoteCodeExec => "ISO 27001:2022 · A.8.8 / A.8.28 (Vulnerabilidades y Código Seguro)".into(),
            VulnCategory::DatabaseAndData => "ISO 27001:2022 · A.8.12 / A.8.24 (Prevención de Fuga y Cifrado)".into(),
            VulnCategory::NetworkPerimeter => "ISO 27001:2022 · A.8.20 / A.8.22 (Seguridad y Segmentación de Redes)".into(),
            VulnCategory::WebAndApi => "ISO 27001:2022 · A.8.26 / A.8.28 (Seguridad en Aplicaciones)".into(),
            VulnCategory::MemoryAndLibraries => "ISO 27001:2022 · A.8.8 / A.8.19 (Gestión de Software y Parches)".into(),
            VulnCategory::GeneralVuln => "ISO 27001:2022 · A.8.8 (Gestión de Vulnerabilidades Técnicas)".into(),
        },
        GrcFramework::NistCsf => match cat {
            VulnCategory::BackdoorAndSupplyChain => "NIST CSF 2.0 · GV.SC-07 / DE.CM-09 (Cadena de Suministro y Malware)".into(),
            VulnCategory::DenialOfService => "NIST CSF 2.0 · PR.IR-04 (Resiliencia y Disponibilidad de Servicios)".into(),
            VulnCategory::AuthAndPrivilege => "NIST CSF 2.0 · PR.AA-01 / PR.AA-05 (Identidades y Privilegios)".into(),
            VulnCategory::RemoteCodeExec => "NIST CSF 2.0 · ID.RA-01 / RS.MI-02 (Mitigación de RCE Crítico)".into(),
            VulnCategory::DatabaseAndData => "NIST CSF 2.0 · PR.DS-01 / PR.DS-02 (Protección de Datos)".into(),
            VulnCategory::NetworkPerimeter => "NIST CSF 2.0 · PR.IR-01 / DE.CM-01 (Perímetro y Monitoreo de Red)".into(),
            VulnCategory::WebAndApi => "NIST CSF 2.0 · PR.PS-06 (Desarrollo y Despliegue Seguro)".into(),
            VulnCategory::MemoryAndLibraries => "NIST CSF 2.0 · PR.PS-02 (Mantenimiento de Software y Librerías)".into(),
            VulnCategory::GeneralVuln => "NIST CSF 2.0 · ID.RA-01 (Identificación de Vulnerabilidades)".into(),
        },
        GrcFramework::OwaspTop10 => match cat {
            VulnCategory::BackdoorAndSupplyChain => "OWASP A03:2025 · Software Supply Chain Failures".into(),
            VulnCategory::DenialOfService => "OWASP A10:2025 · Mishandling of Exceptional Conditions".into(),
            VulnCategory::AuthAndPrivilege => "OWASP A07:2025 · Authentication Failures".into(),
            VulnCategory::RemoteCodeExec => "OWASP A05:2025 · Injection (RCE / Command Injection)".into(),
            VulnCategory::DatabaseAndData => "OWASP A05:2025 · Injection / A04 Cryptographic Failures".into(),
            VulnCategory::NetworkPerimeter => "OWASP A02:2025 · Security Misconfiguration".into(),
            VulnCategory::WebAndApi => "OWASP A01:2025 · Broken Access Control (incl. SSRF)".into(),
            VulnCategory::MemoryAndLibraries => "OWASP A03:2025 · Software Supply Chain Failures".into(),
            VulnCategory::GeneralVuln => "OWASP A03:2025 · Software Supply Chain Failures".into(),
        },
    }
}

/// Evalúa toda la auditoría y genera la Matriz NxN, el ranking, controles GRC y Riesgo Residual.
pub fn build_matrix_report(audit: &AuditProject) -> MatrixReport {
    let matrix_size = normalize_matrix_size(audit.config.matrix_size);
    let max_score = matrix_size * matrix_size;

    let asset_map: HashMap<&str, &Asset> = audit
        .assets
        .iter()
        .map(|a| (a.id.as_str(), a))
        .collect();

    let planned_set: HashSet<&str> = audit
        .planned_remediation_ids
        .iter()
        .map(|s| s.as_str())
        .collect();

    let mut items: Vec<RiskItem> = Vec::new();

    for finding in &audit.findings {
        for asset_id in &finding.asset_ids {
            if let Some(asset) = asset_map.get(asset_id.as_str()) {
                let item_id = format!("{}__{}", finding.id, asset.id);
                let suggested_impact = compute_suggested_impact(asset, finding, matrix_size);
                let suggested_likelihood = compute_suggested_likelihood(asset, finding, matrix_size);
                let suggestion_reason = build_suggestion_reason(asset, finding);

                let (impact, likelihood, is_calibrated, auditor_note, custom_control) =
                    if let Some(ov) = audit.overrides.get(&item_id) {
                        (
                            ov.impact.clamp(1, matrix_size),
                            ov.likelihood.clamp(1, matrix_size),
                            true,
                            ov.note.clone(),
                            ov.custom_grc_control.clone(),
                        )
                    } else {
                        (
                            suggested_impact,
                            suggested_likelihood,
                            false,
                            String::new(),
                            None,
                        )
                    };

                let risk_score = impact * likelihood;
                let risk_level = classify_risk_level(risk_score, matrix_size);
                let sla_window = sla_window_for_level(&risk_level);
                let grc_control = custom_control
                    .filter(|s| !s.trim().is_empty())
                    .unwrap_or_else(|| map_grc_control(&audit.config.framework, asset, finding));
                let in_remediation_plan = planned_set.contains(item_id.as_str());

                items.push(RiskItem {
                    id: item_id,
                    finding_id: finding.id.clone(),
                    cve_id: finding.cve_id.clone(),
                    title: finding.title.clone(),
                    asset_id: asset.id.clone(),
                    asset_name: asset.name.clone(),
                    asset_host: asset.host.clone(),
                    asset_type: asset.asset_type.clone(),
                    exposure: asset.exposure.clone(),
                    asset_criticality: asset.criticality,
                    cvss: finding.cvss,
                    epss: finding.epss,
                    in_kev: finding.in_kev,
                    status: finding.status.clone(),
                    suggested_impact,
                    suggested_likelihood,
                    suggestion_reason,
                    impact,
                    likelihood,
                    is_calibrated,
                    auditor_note,
                    risk_score,
                    max_score,
                    risk_level,
                    sla_window,
                    grc_control,
                    remediation: finding.remediation.clone(),
                    in_remediation_plan,
                });
            }
        }
    }

    items.sort_by(|a, b| {
        let a_open = a.status == FindingStatus::Open;
        let b_open = b.status == FindingStatus::Open;
        b_open
            .cmp(&a_open)
            .then_with(|| b.risk_score.cmp(&a.risk_score))
            .then_with(|| b.in_kev.cmp(&a.in_kev))
            .then_with(|| b.cvss.total_cmp(&a.cvss))
    });

    // Construimos las N*N celdas (Impacto N..=1, Probabilidad 1..=N)
    let mut cells: Vec<MatrixCell> = Vec::with_capacity((matrix_size * matrix_size) as usize);
    for impact in (1..=matrix_size).rev() {
        for likelihood in 1..=matrix_size {
            let matching_ids: Vec<String> = items
                .iter()
                .filter(|it| {
                    it.status == FindingStatus::Open
                        && it.impact == impact
                        && it.likelihood == likelihood
                })
                .map(|it| it.id.clone())
                .collect();

            let score = impact * likelihood;
            cells.push(MatrixCell {
                impact,
                likelihood,
                score,
                level: classify_risk_level(score, matrix_size),
                count: matching_ids.len(),
                item_ids: matching_ids,
            });
        }
    }

    // Métricas Actuales (riesgos abiertos)
    let open_items: Vec<&RiskItem> = items
        .iter()
        .filter(|it| it.status == FindingStatus::Open)
        .collect();

    let critical_count = open_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::Critical)
        .count();
    let high_count = open_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::High)
        .count();
    let medium_count = open_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::Medium)
        .count();
    let low_count = open_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::Low)
        .count();
    let kev_count = open_items.iter().filter(|it| it.in_kev).count();
    let calibrated_count = open_items.iter().filter(|it| it.is_calibrated).count();

    let current_sum: f64 = open_items.iter().map(|it| it.risk_score as f64).sum();
    let current_avg_score = if open_items.is_empty() {
        0.0
    } else {
        ((current_sum / open_items.len() as f64) * 10.0).round() / 10.0
    };

    // Métricas Residuales (excluyendo los marcados en el Plan de Remediación What-If)
    let residual_items: Vec<&RiskItem> = open_items
        .iter()
        .copied()
        .filter(|it| !it.in_remediation_plan)
        .collect();

    let residual_critical_count = residual_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::Critical)
        .count();
    let residual_high_count = residual_items
        .iter()
        .filter(|it| it.risk_level == RiskLevel::High)
        .count();

    let residual_sum: f64 = residual_items.iter().map(|it| it.risk_score as f64).sum();
    let residual_avg_score = if residual_items.is_empty() {
        0.0
    } else {
        ((residual_sum / residual_items.len() as f64) * 10.0).round() / 10.0
    };

    let risk_reduction_pct = if current_sum <= 0.0 {
        0.0
    } else {
        (((current_sum - residual_sum) / current_sum) * 1000.0).round() / 10.0
    };

    let summary = MatrixSummary {
        matrix_size,
        max_score,
        total_assets: audit.assets.len(),
        total_findings: audit.findings.len(),
        open_risk_pairs: open_items.len(),
        critical_count,
        high_count,
        medium_count,
        low_count,
        kev_count,
        calibrated_count,
        current_avg_score,
        residual_open_pairs: residual_items.len(),
        residual_critical_count,
        residual_high_count,
        residual_avg_score,
        risk_reduction_pct,
    };

    MatrixReport {
        summary,
        cells,
        items,
    }
}

/// Genera un reporte ejecutivo en Markdown listo para informes de auditoría / GRC.
pub fn render_markdown_report(audit: &AuditProject) -> String {
    let report = build_matrix_report(audit);
    let n = report.summary.matrix_size;
    let fw_name = match audit.config.framework {
        GrcFramework::Iso27001 => "ISO/IEC 27001:2022",
        GrcFramework::NistCsf => "NIST CSF 2.0",
        GrcFramework::CisControls => "CIS Controls v8",
        GrcFramework::OwaspTop10 => "OWASP Top 10:2025",
    };

    let mut md = String::new();
    md.push_str(&format!("# Informe de Gestión de Riesgos — {}\n\n", audit.name));
    md.push_str(&format!("- **Organización:** {}\n", audit.client));
    md.push_str(&format!("- **Auditor:** {}\n", audit.auditor));
    md.push_str(&format!("- **Fecha:** {}\n", audit.date));
    md.push_str(&format!("- **Metodología:** Matriz {}×{} · Marco {}\n\n", n, n, fw_name));

    md.push_str("## 1. Riesgo Actual vs. Riesgo Residual (Plan de Remediación)\n\n");
    md.push_str("| Indicador | Riesgo Actual | Riesgo Residual (Post-Remediación) |\n");
    md.push_str("| :--- | :---: | :---: |\n");
    md.push_str(&format!(
        "| Exposiciones abiertas | {} | {} |\n",
        report.summary.open_risk_pairs, report.summary.residual_open_pairs
    ));
    md.push_str(&format!(
        "| Riesgos Críticos | **{}** | **{}** |\n",
        report.summary.critical_count, report.summary.residual_critical_count
    ));
    md.push_str(&format!(
        "| Riesgos Altos | {} | {} |\n",
        report.summary.high_count, report.summary.residual_high_count
    ));
    md.push_str(&format!(
        "| Promedio de Riesgo (1–{}) | {:.1} | {:.1} |\n",
        report.summary.max_score, report.summary.current_avg_score, report.summary.residual_avg_score
    ));
    md.push_str(&format!(
        "| Reducción total de riesgo estimada | — | **-{:.1}%** |\n\n",
        report.summary.risk_reduction_pct
    ));

    md.push_str(&format!("## 2. Matriz de Impacto vs. Probabilidad ({}×{})\n\n", n, n));
    md.push_str("| Impacto \\ Probabilidad |");
    for l in 1..=n {
        md.push_str(&format!(" P{} |", l));
    }
    md.push('\n');
    md.push_str("| :--- |");
    for _ in 1..=n {
        md.push_str(" :---: |");
    }
    md.push('\n');

    for impact in (1..=n).rev() {
        let mut row = format!("| **I{}** |", impact);
        for likelihood in 1..=n {
            let count = report
                .cells
                .iter()
                .find(|c| c.impact == impact && c.likelihood == likelihood)
                .map(|c| c.count)
                .unwrap_or(0);
            if count > 0 {
                row.push_str(&format!(" **{}** |", count));
            } else {
                row.push_str(" · |");
            }
        }
        row.push('\n');
        md.push_str(&row);
    }

    md.push_str("\n## 3. Plan de Remediación Priorizado (con SLA y Controles)\n\n");
    md.push_str("| # | CVE | Activo | Nivel | Plazo SLA | Score | Control | Criterio / Nota |\n");
    md.push_str("| :---: | :--- | :--- | :---: | :---: | :---: | :--- | :--- |\n");

    let open_items: Vec<&RiskItem> = report
        .items
        .iter()
        .filter(|i| i.status == FindingStatus::Open)
        .collect();

    for (idx, item) in open_items.iter().enumerate() {
        let level_label = match item.risk_level {
            RiskLevel::Critical => "CRÍTICO",
            RiskLevel::High => "ALTO",
            RiskLevel::Medium => "MEDIO",
            RiskLevel::Low => "BAJO",
        };
        let note = if item.is_calibrated {
            if item.auditor_note.is_empty() {
                "Calibrado por auditor".to_string()
            } else {
                format!("Calibrado: {}", item.auditor_note)
            }
        } else {
            "Sugerencia automática".to_string()
        };
        md.push_str(&format!(
            "| {} | `{}` | {} | **{}** | {} | {}/{} | {} | {} |\n",
            idx + 1,
            item.cve_id,
            item.asset_name,
            level_label,
            item.sla_window,
            item.risk_score,
            item.max_score,
            item.grc_control,
            note
        ));
    }

    // Sección 4: Resumen de Brechas por Control del Marco
    if !open_items.is_empty() {
        let mut control_counts: HashMap<&str, usize> = HashMap::new();
        for item in &open_items {
            *control_counts.entry(item.grc_control.as_str()).or_insert(0) += 1;
        }
        let mut ranked_controls: Vec<(&str, usize)> = control_counts.into_iter().collect();
        ranked_controls.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(b.0)));

        md.push_str(&format!("\n## 4. Concentración de Brechas ({})\n\n", fw_name));
        md.push_str("| Control / Categoría | Hallazgos | % del Total |\n");
        md.push_str("| :--- | :---: | :---: |\n");
        let total = open_items.len() as f64;
        for (ctrl, count) in ranked_controls {
            let pct = ((count as f64 / total) * 1000.0).round() / 10.0;
            md.push_str(&format!("| {} | **{}** | {:.1}% |\n", ctrl, count, pct));
        }
    }

    md
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sample::sample_audit;

    #[test]
    fn test_critical_kev_on_internet_asset_is_critical() {
        let asset = Asset {
            id: "a1".into(),
            name: "Portal Público".into(),
            host: "203.0.113.10".into(),
            asset_type: AssetType::WebApp,
            exposure: Exposure::Internet,
            criticality: 5,
            owner: "Equipo Web".into(),
        };
        let finding = Finding {
            id: "f1".into(),
            cve_id: "CVE-2024-9999".into(),
            title: "RCE Crítico".into(),
            description: "Ejecución remota de código".into(),
            cvss: 9.8,
            epss: 88.5,
            in_kev: true,
            status: FindingStatus::Open,
            asset_ids: vec!["a1".into()],
            remediation: "Actualizar inmediatamente".into(),
            cwe: "CWE-78".into(),
        };

        let impact = compute_suggested_impact(&asset, &finding, 5);
        let likelihood = compute_suggested_likelihood(&asset, &finding, 5);
        assert_eq!(impact, 5);
        assert_eq!(likelihood, 5);
        assert_eq!(classify_risk_level(impact * likelihood, 5), RiskLevel::Critical);
    }

    #[test]
    fn test_matrix_scales_and_residual_risk() {
        let mut audit = sample_audit();
        let report_5 = build_matrix_report(&audit);
        assert_eq!(report_5.cells.len(), 25);
        assert!(report_5.summary.risk_reduction_pct > 0.0);

        audit.config.matrix_size = 3;
        let report_3 = build_matrix_report(&audit);
        assert_eq!(report_3.cells.len(), 9);
    }
}
