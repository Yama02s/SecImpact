use std::collections::{HashMap, HashSet};

use serde::{Deserialize, Serialize};

use crate::models::{Asset, AssetType, Exposure, Finding, FindingStatus};

const MAX_XML_BYTES: usize = 15 * 1024 * 1024; // 15 MB límite de seguridad

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct NmapImportResult {
    pub assets: Vec<Asset>,
    pub findings: Vec<Finding>,
    pub hosts_parsed: usize,
    pub open_ports_total: usize,
    pub cves_found: usize,
}

/// Extrae el valor de un atributo XML `attr="value"` dentro de una etiqueta.
fn extract_attr(tag: &str, attr_name: &str) -> Option<String> {
    let double_pat = format!("{}=\"", attr_name);
    if let Some(start) = tag.find(&double_pat) {
        let rest = &tag[start + double_pat.len()..];
        if let Some(end) = rest.find('"') {
            return Some(unescape_xml(&rest[..end]));
        }
    }
    let single_pat = format!("{}='", attr_name);
    if let Some(start) = tag.find(&single_pat) {
        let rest = &tag[start + single_pat.len()..];
        if let Some(end) = rest.find('\'') {
            return Some(unescape_xml(&rest[..end]));
        }
    }
    None
}

fn unescape_xml(s: &str) -> String {
    s.replace("&quot;", "\"")
        .replace("&apos;", "'")
        .replace("&lt;", "<")
        .replace("&gt;", ">")
        .replace("&amp;", "&")
}

/// Encuentra todos los bloques `<tag ...>...</tag>` (sin soporte de anidación recursiva del mismo tag).
fn find_blocks<'a>(xml: &'a str, tag_name: &str) -> Vec<&'a str> {
    let open_pat = format!("<{}", tag_name);
    let close_pat = format!("</{}>", tag_name);
    let mut blocks = Vec::new();
    let mut cursor = 0;

    while let Some(rel_start) = xml[cursor..].find(&open_pat) {
        let start = cursor + rel_start;
        // Verificar que el carácter tras el nombre del tag sea espacio, '>' o '/'
        let after_name = start + open_pat.len();
        if let Some(next_ch) = xml[after_name..].chars().next() {
            if !next_ch.is_whitespace() && next_ch != '>' && next_ch != '/' {
                cursor = after_name;
                continue;
            }
        }
        if let Some(rel_end) = xml[start..].find(&close_pat) {
            let end = start + rel_end + close_pat.len();
            blocks.push(&xml[start..end]);
            cursor = end;
        } else {
            break;
        }
    }
    blocks
}

/// Encuentra todas las etiquetas que comienzan con `<tag_name ...>`.
fn find_tags<'a>(xml: &'a str, tag_name: &str) -> Vec<&'a str> {
    let open_pat = format!("<{}", tag_name);
    let mut tags = Vec::new();
    let mut cursor = 0;

    while let Some(rel_start) = xml[cursor..].find(&open_pat) {
        let start = cursor + rel_start;
        let after_name = start + open_pat.len();
        if let Some(next_ch) = xml[after_name..].chars().next() {
            if !next_ch.is_whitespace() && next_ch != '>' && next_ch != '/' {
                cursor = after_name;
                continue;
            }
        }
        if let Some(rel_end) = xml[start..].find('>') {
            let end = start + rel_end + 1;
            tags.push(&xml[start..end]);
            cursor = end;
        } else {
            break;
        }
    }
    tags
}

/// Extrae todos los códigos `CVE-YYYY-NNNN...` de un texto arbitrario.
fn extract_cves(text: &str) -> Vec<String> {
    let upper = text.to_uppercase();
    let bytes = upper.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;

    while i + 9 <= bytes.len() {
        if &bytes[i..i + 4] == b"CVE-" {
            let mut j = i + 4;
            // 4 dígitos de año
            let year_start = j;
            while j < bytes.len() && bytes[j].is_ascii_digit() {
                j += 1;
            }
            if j - year_start == 4 && j < bytes.len() && bytes[j] == b'-' {
                j += 1;
                let num_start = j;
                while j < bytes.len() && bytes[j].is_ascii_digit() {
                    j += 1;
                }
                let num_len = j - num_start;
                if (4..=7).contains(&num_len) {
                    found.push(upper[i..j].to_string());
                    i = j;
                    continue;
                }
            }
        }
        i += 1;
    }
    found
}

/// Infiere la exposición de red según dirección IP (RFC 1918 vs pública).
fn infer_exposure(ip: &str) -> Exposure {
    if ip.starts_with("10.") || ip.starts_with("192.168.") || ip.starts_with("127.") {
        Exposure::Internal
    } else if let Some(rest) = ip.strip_prefix("172.") {
        if let Some(second) = rest.split('.').next().and_then(|s| s.parse::<u8>().ok()) {
            if (16..=31).contains(&second) {
                return Exposure::Dmz;
            }
        }
        Exposure::Internet
    } else if ip.contains(':') && (ip.starts_with("fe80:") || ip.starts_with("fc") || ip.starts_with("fd")) {
        Exposure::Internal
    } else {
        Exposure::Internet
    }
}

/// Infiere el tipo de activo y criticidad base según puertos y servicios abiertos.
fn infer_asset_type(ports: &[(u16, String)], exposure: &Exposure) -> (AssetType, u8) {
    let has_port = |p: u16| ports.iter().any(|(port, _)| *port == p);
    let has_svc = |kw: &str| {
        ports
            .iter()
            .any(|(_, svc)| svc.to_lowercase().contains(kw))
    };

    if has_port(88) || has_port(389) || has_port(636) || has_svc("kerberos") || has_svc("ldap") {
        (AssetType::ActiveDirectory, 5)
    } else if has_port(3306)
        || has_port(5432)
        || has_port(1433)
        || has_port(27017)
        || has_port(6379)
        || has_port(1521)
        || has_svc("mysql")
        || has_svc("postgres")
        || has_svc("mssql")
        || has_svc("mongodb")
    {
        (AssetType::Database, 5)
    } else if has_port(80)
        || has_port(443)
        || has_port(8080)
        || has_port(8443)
        || has_svc("http")
    {
        let crit = if *exposure == Exposure::Internet { 4 } else { 3 };
        (AssetType::WebApp, crit)
    } else if has_port(500) || has_port(1194) || has_port(161) || has_svc("vpn") {
        (AssetType::Network, 4)
    } else {
        let crit = if *exposure == Exposure::Internet { 4 } else { 3 };
        (AssetType::Server, crit)
    }
}

/// Parsea un archivo XML generado por Nmap (`nmap -oX scan.xml`).
/// No expande entidades XML externas (seguro contra XXE).
pub fn parse_nmap_xml(xml: &str) -> Result<NmapImportResult, String> {
    if xml.len() > MAX_XML_BYTES {
        return Err("El archivo XML supera el límite de 15 MB.".into());
    }
    if xml.contains("<!ENTITY") {
        return Err("El archivo XML contiene declaraciones ENTITY no permitidas (protección XXE).".into());
    }
    if !xml.contains("<nmaprun") {
        return Err("El archivo no parece ser una salida válida de Nmap XML (falta <nmaprun>).".into());
    }

    let host_blocks = find_blocks(xml, "host");
    let mut assets: Vec<Asset> = Vec::new();
    let mut open_ports_total: usize = 0;
    // cve_id -> (Vec<asset_id>, contexto de servicio)
    let mut cve_map: HashMap<String, (Vec<String>, String)> = HashMap::new();

    for (idx, host_xml) in host_blocks.iter().enumerate() {
        // Ignorar hosts caídos (state="down")
        if let Some(status_tag) = find_tags(host_xml, "status").first() {
            if extract_attr(status_tag, "state").as_deref() == Some("down") {
                continue;
            }
        }

        // Dirección IP (priorizar ipv4/ipv6 sobre mac)
        let mut ip = String::new();
        for addr_tag in find_tags(host_xml, "address") {
            let addr_type = extract_attr(addr_tag, "addrtype").unwrap_or_default();
            if addr_type == "ipv4" || addr_type == "ipv6" {
                if let Some(val) = extract_attr(addr_tag, "addr") {
                    ip = val;
                    break;
                }
            }
        }
        if ip.is_empty() {
            continue;
        }

        // Hostname si existe
        let hostname = find_tags(host_xml, "hostname")
            .first()
            .and_then(|t| extract_attr(t, "name"));

        // Puertos abiertos y CVEs de scripts NSE (ej. vulners / vuln)
        let mut open_ports: Vec<(u16, String)> = Vec::new();
        let mut host_cves: HashSet<String> = HashSet::new();

        for port_block in find_blocks(host_xml, "port") {
            let is_open = find_tags(port_block, "state")
                .first()
                .and_then(|t| extract_attr(t, "state"))
                .map(|s| s == "open" || s == "open|filtered")
                .unwrap_or(false);

            if !is_open {
                continue;
            }

            let port_num = find_tags(port_block, "port")
                .first()
                .and_then(|t| extract_attr(t, "portid"))
                .and_then(|p| p.parse::<u16>().ok())
                .unwrap_or(0);

            let svc_label = find_tags(port_block, "service")
                .first()
                .map(|t| {
                    let name = extract_attr(t, "name").unwrap_or_else(|| "unknown".into());
                    let product = extract_attr(t, "product").unwrap_or_default();
                    let version = extract_attr(t, "version").unwrap_or_default();
                    if !product.is_empty() {
                        format!("{} ({} {})", name, product, version).trim().to_string()
                    } else {
                        name
                    }
                })
                .unwrap_or_else(|| "unknown".into());

            if port_num > 0 {
                open_ports.push((port_num, svc_label.clone()));
                open_ports_total += 1;
            }

            // Buscar CVEs en scripts del puerto (ej. vulners, smb-vuln-*, http-vuln-*)
            for script_tag in find_tags(port_block, "script") {
                if let Some(output) = extract_attr(script_tag, "output") {
                    for cve in extract_cves(&output) {
                        host_cves.insert(cve);
                    }
                }
            }
            for cve in extract_cves(port_block) {
                host_cves.insert(cve);
            }
        }

        // También revisar scripts a nivel de <hostscript>
        for hs_block in find_blocks(host_xml, "hostscript") {
            for cve in extract_cves(hs_block) {
                host_cves.insert(cve);
            }
        }

        let exposure = infer_exposure(&ip);
        let (asset_type, criticality) = infer_asset_type(&open_ports, &exposure);
        let asset_id = format!("nmap-{}-{}", ip.replace(['.', ':'], "-"), idx + 1);

        let ports_summary = if open_ports.is_empty() {
            String::new()
        } else {
            let list: Vec<String> = open_ports
                .iter()
                .take(5)
                .map(|(p, s)| format!("{}/{}", p, s.split(' ').next().unwrap_or("tcp")))
                .collect();
            let extra = if open_ports.len() > 5 {
                format!(" +{}", open_ports.len() - 5)
            } else {
                String::new()
            };
            format!(" · puertos: {}{}", list.join(", "), extra)
        };

        let asset_name = hostname
            .clone()
            .unwrap_or_else(|| format!("Host {}", ip));

        assets.push(Asset {
            id: asset_id.clone(),
            name: asset_name.clone(),
            host: format!("{}{}", ip, ports_summary),
            asset_type,
            exposure,
            criticality,
            owner: "Importado desde Nmap".into(),
        });

        for cve in host_cves {
            let entry = cve_map
                .entry(cve)
                .or_insert_with(|| (Vec::new(), format!("Detectado por Nmap en {}", asset_name)));
            if !entry.0.contains(&asset_id) {
                entry.0.push(asset_id.clone());
            }
        }
    }

    let mut findings: Vec<Finding> = cve_map
        .into_iter()
        .enumerate()
        .map(|(i, (cve_id, (asset_ids, context)))| Finding {
            id: format!("nmap-cve-{}-{}", i + 1, cve_id),
            cve_id: cve_id.clone(),
            title: format!("Vulnerabilidad detectada por Nmap ({})", cve_id),
            description: context,
            cvss: 7.5,
            epss: 25.0,
            in_kev: false,
            status: FindingStatus::Open,
            asset_ids,
            remediation: "Verificar versión del servicio detectado y aplicar parche oficial.".into(),
            cwe: String::new(),
        })
        .collect();

    findings.sort_by(|a, b| a.cve_id.cmp(&b.cve_id));

    let hosts_parsed = assets.len();
    let cves_found = findings.len();

    Ok(NmapImportResult {
        assets,
        findings,
        hosts_parsed,
        open_ports_total,
        cves_found,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_nmap_xml_hosts_ports_and_cves() {
        let sample_xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<nmaprun scanner="nmap" args="nmap -sV --script vulners -oX scan.xml">
  <host>
    <status state="up" />
    <address addr="203.0.113.10" addrtype="ipv4" />
    <hostnames><hostname name="web.empresa.cl" type="PTR" /></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open" />
        <service name="https" product="Apache httpd" version="2.4.49" />
        <script id="vulners" output="CVE-2021-41773 9.8 https://vulners.com/cve/CVE-2021-41773" />
      </port>
      <port protocol="tcp" portid="22">
        <state state="open" />
        <service name="ssh" product="OpenSSH" version="8.2p1" />
      </port>
    </ports>
  </host>
  <host>
    <status state="up" />
    <address addr="10.0.0.5" addrtype="ipv4" />
    <ports>
      <port protocol="tcp" portid="3306">
        <state state="open" />
        <service name="mysql" product="MySQL" version="8.0" />
      </port>
    </ports>
  </host>
  <host>
    <status state="down" />
    <address addr="10.0.0.99" addrtype="ipv4" />
  </host>
</nmaprun>"#;

        let res = parse_nmap_xml(sample_xml).expect("Debe parsear Nmap XML válido");
        assert_eq!(res.hosts_parsed, 2);
        assert_eq!(res.open_ports_total, 3);
        assert_eq!(res.cves_found, 1);
        assert_eq!(res.assets[0].name, "web.empresa.cl");
        assert_eq!(res.assets[0].exposure, Exposure::Internet);
        assert_eq!(res.assets[0].asset_type, AssetType::WebApp);
        assert_eq!(res.assets[1].exposure, Exposure::Internal);
        assert_eq!(res.assets[1].asset_type, AssetType::Database);
        assert_eq!(res.findings[0].cve_id, "CVE-2021-41773");
    }

    #[test]
    fn test_rejects_xxe_entity() {
        let bad = "<!DOCTYPE foo [ <!ENTITY xxe SYSTEM 'file:///etc/passwd'> ]><nmaprun></nmaprun>";
        assert!(parse_nmap_xml(bad).is_err());
    }
}
