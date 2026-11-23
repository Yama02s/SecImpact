# SecImpact

Herramienta Open Source de escritorio para **Gestión de Riesgos, Gobernanza y Documentación Post-Pentesting (GRC)**.

**SecImpact** transforma los hallazgos técnicos de una auditoría en entregables claros de gestión de riesgos: **Matriz de Impacto interactiva (3×3, 4×4 o 5×5)** con calibración Drag & Drop, **Mapa de Exposición por Zonas**, simulador de **Riesgo Actual vs. Riesgo Residual (What-If)** y un **Report Kit** con imágenes PNG/SVG listas para informes Word/PDF y tablas Markdown.

## Características (v0.3.0)

- **Ingesta Post-Pentest:**
  - Importador de **Nmap XML** (`nmap -sV --script vulners -oX scan.xml`) con detección automática de hosts, puertos, tipo de activo, criticidad y exposición.
  - Importador de **Nuclei (`.jsonl`)** y pegado rápido de CVEs.
  - Enriquecimiento automático desde APIs oficiales de **NVD (NIST)**, **FIRST EPSS** y **CISA KEV**.
- **Matriz de Impacto & Calibración con Criterio Humano:**
  - Escalas seleccionables **5×5**, **4×4** y **3×3**.
  - **Drag & Drop** entre celdas + **Inspector Derecho** para ajustar Impacto/Probabilidad y documentar la justificación de criterio del auditor.
  - Simulador **Riesgo Actual vs. Riesgo Residual (What-If)** y plazos **SLA** sugeridos (`24–72h`, `7–15 días`, `30 días`, `90 días`).
- **Marcos GRC y AppSec Integrados:**
  - **CIS Controls v8**
  - **ISO/IEC 27001:2022**
  - **NIST CSF 2.0**
  - **OWASP Top 10:2025**
- **Mapa de Exposición por Zonas:** visualización de activos desde `Internet → DMZ → Red Interna` con reasignación rápida y exportación a PNG/SVG.
- **Report Kit para Informes Finales:**
  - Exportación de **Matriz** (con etiquetas `R1..Rn`, ejes descriptivos y tabla de referencia integrada) y **Mapa de Zonas** en **PNG (2x)** y **SVG** en **Fondo Claro (Word/PDF)** u **Oscuro**.
  - Informe ejecutivo en **Markdown** con concentración de brechas por control.
- **Seguridad aplicada:** servidor de desarrollo restringido a `localhost`, protección XXE en Nmap XML, sanitización de nombres de archivo contra Path Traversal, escape XML/sanitización SVG contra XSS y política CSP estricta.

## Stack Tecnológico

- **Backend / Motor:** Rust + Tauri v2
- **Frontend:** React 18 + TypeScript + Vite + Tailwind CSS

## Requisitos previos

- [Node.js](https://nodejs.org/) (v18+)
- [Rust (`rustup`)](https://rustup.rs/)
- En Windows: **Microsoft C++ Build Tools** (MSVC + Windows SDK)

## Desarrollo local

```bash
# 1. Instalar dependencias de frontend
npm install

# 2. Ejecutar la aplicación de escritorio
npm run tauri dev

# 3. Ejecutar los tests unitarios en Rust
cd src-tauri && cargo test
```

## Roadmap

- [x] **v0.3.0:** Matriz 3×3/4×4/5×5 Drag & Drop, enriquecimiento NVD + EPSS + CISA KEV, CIS v8 / ISO 27001 / NIST CSF 2.0 / OWASP Top 10:2025, importador Nmap XML y Nuclei JSONL, Mapa de Exposición por Zonas, simulador Residual What-If, Report Kit (PNG/SVG/Markdown) y Ajustes (ES/EN + Tema Oscuro/Claro).
- [ ] **v0.4.0:** Lienzo visual libre estilo Excalidraw/BloodHound para diagramar rutas de ataque y *blast radius*, importador Nessus/OpenVAS/CSV y exportación directa a PDF.

## Licencia

Distribuido bajo licencia [MIT](LICENSE).
