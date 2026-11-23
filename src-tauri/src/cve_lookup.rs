use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CveEnrichment {
    pub cve_id: String,
    pub found: bool,
    pub title: String,
    pub description: String,
    pub cvss: f64,
    pub epss: f64,
    pub in_kev: bool,
    pub cwe: String,
}

static KEV_CACHE: OnceLock<Mutex<Option<HashSet<String>>>> = OnceLock::new();

/// Obtiene el conjunto de CVEs presentes en el catálogo oficial CISA KEV (con caché en memoria).
async fn is_cve_in_kev(client: &reqwest::Client, clean_cve: &str) -> bool {
    let cache = KEV_CACHE.get_or_init(|| Mutex::new(None));

    if let Ok(guard) = cache.lock() {
        if let Some(ref set) = *guard {
            return set.contains(clean_cve);
        }
    }

    let kev_url =
        "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
    if let Ok(resp) = client.get(kev_url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(vulns) = json.get("vulnerabilities").and_then(|v| v.as_array()) {
                    let set: HashSet<String> = vulns
                        .iter()
                        .filter_map(|v| v.get("cveID").and_then(|id| id.as_str()))
                        .map(|s| s.trim().to_uppercase())
                        .collect();
                    let found = set.contains(clean_cve);
                    if let Ok(mut guard) = cache.lock() {
                        *guard = Some(set);
                    }
                    return found;
                }
            }
        }
    }

    false
}

/// Consulta las APIs públicas oficiales de NVD (NIST), FIRST EPSS y CISA KEV para enriquecer un CVE.
pub async fn fetch_cve_enrichment(cve_id: &str) -> Result<CveEnrichment, String> {
    let clean_cve = cve_id.trim().to_uppercase();
    // Validación estricta de formato CVE-YYYY-NNNN... para evitar SSRF/inyección en URL
    let valid_chars = clean_cve
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-');
    if !valid_chars || !clean_cve.starts_with("CVE-") || clean_cve.len() > 24 {
        return Err("Formato de CVE inválido".into());
    }

    let client = reqwest::Client::builder()
        .user_agent("SecImpact/0.3")
        .timeout(std::time::Duration::from_secs(12))
        .build()
        .map_err(|e| format!("Error creando cliente HTTP: {e}"))?;

    // 1. Consulta a NVD API v2
    let nvd_url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={}",
        clean_cve
    );
    let mut found = false;
    let mut description = String::new();
    let mut cvss: f64 = 7.5;
    let mut cwe = String::new();

    if let Ok(resp) = client.get(&nvd_url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(cve_obj) = json
                    .get("vulnerabilities")
                    .and_then(|v| v.as_array())
                    .and_then(|arr| arr.first())
                    .and_then(|item| item.get("cve"))
                {
                    found = true;

                    if let Some(descs) = cve_obj.get("descriptions").and_then(|d| d.as_array()) {
                        let es = descs
                            .iter()
                            .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("es"))
                            .and_then(|d| d.get("value").and_then(|v| v.as_str()));
                        let en = descs
                            .iter()
                            .find(|d| d.get("lang").and_then(|l| l.as_str()) == Some("en"))
                            .and_then(|d| d.get("value").and_then(|v| v.as_str()));
                        if let Some(text) = es.or(en) {
                            description = text.to_string();
                        }
                    }

                    if let Some(metrics) = cve_obj.get("metrics") {
                        let score = metrics
                            .get("cvssMetricV31")
                            .and_then(|m| m.as_array())
                            .and_then(|a| a.first())
                            .and_then(|x| x.get("cvssData"))
                            .and_then(|d| d.get("baseScore"))
                            .and_then(|s| s.as_f64())
                            .or_else(|| {
                                metrics
                                    .get("cvssMetricV30")
                                    .and_then(|m| m.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|x| x.get("cvssData"))
                                    .and_then(|d| d.get("baseScore"))
                                    .and_then(|s| s.as_f64())
                            })
                            .or_else(|| {
                                metrics
                                    .get("cvssMetricV2")
                                    .and_then(|m| m.as_array())
                                    .and_then(|a| a.first())
                                    .and_then(|x| x.get("cvssData"))
                                    .and_then(|d| d.get("baseScore"))
                                    .and_then(|s| s.as_f64())
                            });
                        if let Some(s) = score {
                            cvss = s;
                        }
                    }

                    if let Some(weaknesses) = cve_obj.get("weaknesses").and_then(|w| w.as_array()) {
                        for w in weaknesses {
                            if let Some(val) = w
                                .get("description")
                                .and_then(|d| d.as_array())
                                .and_then(|a| a.first())
                                .and_then(|x| x.get("value"))
                                .and_then(|v| v.as_str())
                            {
                                if val.starts_with("CWE-") {
                                    cwe = val.to_string();
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    // 2. Consulta a FIRST EPSS API
    let epss_url = format!("https://api.first.org/data/v1/epss?cve={}", clean_cve);
    let mut epss: f64 = 25.0;
    if let Ok(resp) = client.get(&epss_url).send().await {
        if resp.status().is_success() {
            if let Ok(json) = resp.json::<Value>().await {
                if let Some(epss_str) = json
                    .get("data")
                    .and_then(|d| d.as_array())
                    .and_then(|a| a.first())
                    .and_then(|x| x.get("epss"))
                    .and_then(|v| v.as_str())
                {
                    if let Ok(val) = epss_str.parse::<f64>() {
                        epss = ((val * 100.0) * 10.0).round() / 10.0;
                    }
                }
            }
        }
    }

    // 3. Consulta a CISA KEV (con caché por sesión)
    let in_kev = is_cve_in_kev(&client, &clean_cve).await;

    let title = if !description.is_empty() {
        let first_sentence = description
            .split(". ")
            .next()
            .unwrap_or(&description)
            .trim();
        if first_sentence.chars().count() > 95 {
            let truncated: String = first_sentence.chars().take(92).collect();
            format!("{}...", truncated)
        } else {
            first_sentence.to_string()
        }
    } else {
        format!("Vulnerabilidad sin registro NVD ({})", clean_cve)
    };

    Ok(CveEnrichment {
        cve_id: clean_cve,
        found,
        title,
        description,
        cvss,
        epss,
        in_kev,
        cwe,
    })
}
