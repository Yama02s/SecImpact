# SecImpact

Herramienta Open Source de escritorio para **Gestión de Riesgos, Gobernanza y Documentación Post-Pentesting (GRC)**.

**SecImpact** transforma hallazgos técnicos de una auditoría en entregables ejecutivos de gestión de riesgos: **Matriz de Impacto interactiva (3×3, 4×4 o 5×5)** con calibración Drag & Drop, **Mapa de Exposición por Zonas**, simulador de **Riesgo Actual vs. Riesgo Residual (What-If)** y un **Report Kit** con imágenes PNG/SVG listas para informes Word/PDF y tablas Markdown.

---

## Características (v0.3.0)

- **Ingesta Post-Pentest:**
  - Importador de **Nmap XML** (`nmap -sV --script vulners -oX scan.xml`) con detección automática de hosts, puertos abiertos, tipo de activo, criticidad y exposición.
  - Importador de **Nuclei (`.jsonl`)** y pegado rápido de CVEs.
  - Enriquecimiento automático mediante APIs públicas de **NVD (NIST)**, **FIRST EPSS** y **CISA KEV**.
- **Matriz de Impacto & Calibración con Criterio Humano:**
  - Escalas seleccionables **5×5**, **4×4** y **3×3**.
  - **Drag & Drop** entre celdas + **Inspector Derecho** para ajustar Impacto/Probabilidad y documentar la justificación del auditor.
  - Simulador **Riesgo Actual vs. Riesgo Residual (What-If)** y plazos **SLA** sugeridos (`24–72h`, `7–15 días`, `30 días`, `90 días`).
- **Marcos GRC y AppSec:**
  - **CIS Controls v8**
  - **ISO/IEC 27001:2022**
  - **NIST CSF 2.0**
  - **OWASP Top 10:2025**
- **Mapa de Exposición por Zonas:** visualización interactiva `Internet → DMZ → Red Interna` con reasignación rápida y exportación a PNG/SVG.
- **Report Kit:** exportación de Matriz (con etiquetas `R1..Rn`, ejes descriptivos y tabla de referencia integrada) y Mapa de Zonas en **PNG (2x)** y **SVG** en **Fondo Claro (Word/PDF)** u **Oscuro**, más informe ejecutivo en **Markdown**.
- **Personalización:** interfaz bilingüe (**Español / English**) y selector de tema (**Oscuro / Claro**).
- **Seguridad aplicada:** servidor de desarrollo restringido a `localhost`, protección XXE en Nmap XML, sanitización contra Path Traversal, escape XML/sanitización SVG contra XSS y CSP estricta.

---

## Instalación y Uso

### 1. Clonar el repositorio

```bash
git clone https://github.com/Yama02s/SecImpact.git
cd SecImpact
```

### 2. Requisitos previos según tu sistema operativo

#### Windows (10 / 11)
1. **Node.js (v18+):** descargar desde [nodejs.org](https://nodejs.org/).
2. **Microsoft C++ Build Tools:** instalar con la carga de trabajo *"Desarrollo para el escritorio con C++"* desde [Visual Studio Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/).
3. **Rust (`rustup`):**
   ```powershell
   winget install Rustlang.Rustup
   ```
   *(Cierra y vuelve a abrir la terminal para recargar el `PATH`).*

#### Linux (Linux Mint / Ubuntu / Debian)
1. **Dependencias del sistema (WebKitGTK y compilador C):**
   ```bash
   sudo apt update
   sudo apt install -y libwebkit2gtk-4.1-dev build-essential curl wget file \
     libxdo-dev libssl-dev libayatana-appindicator3-dev librsvg2-dev
   ```
2. **Node.js (v18+)** y **Rust (`rustup`):**
   ```bash
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source "$HOME/.cargo/env"
   ```

### 3. Instalar dependencias y ejecutar

```bash
# Instalar dependencias del frontend
npm install

# Ejecutar la aplicación de escritorio
npm run tauri dev
```

*(La primera compilación de Rust tarda entre 1 y 2 minutos; las siguientes inician en segundos).*

### 4. Ejecutar pruebas unitarias (opcional)

```bash
cd src-tauri
cargo test
```

---

## Stack Tecnológico

- **Backend:** Rust + Tauri v2
- **Frontend:** React 18 + TypeScript + Vite + Tailwind CSS

## Licencia

Distribuido bajo licencia [MIT](LICENSE) — © 2026 Meraav (`Yama02s`).
