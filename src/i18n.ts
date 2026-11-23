export type Language = "es" | "en";
export type AppTheme = "dark" | "light";

const DICT = {
  es: {
    projects: "Proyectos",
    settings: "Ajustes",
    settingsTitle: "Ajustes de SecImpact",
    languageLabel: "Idioma de la interfaz",
    themeLabel: "Apariencia",
    themeDark: "Oscuro",
    themeLight: "Claro",
    close: "Cerrar",
    workflowTitle: "Flujo de Auditoría",
    stepIngest: "Ingesta",
    stepIngestSub: "Importar hallazgos",
    stepMatrix: "Matriz & Riesgo",
    stepMatrixSub: "Calibrar y simular",
    stepZoneMap: "Mapa de Zonas",
    stepZoneMapSub: "Internet → DMZ → Red",
    stepInventory: "Inventario",
    stepInventorySub: "Activos y CVEs",
    stepReport: "Report Kit",
    stepReportSub: "PNG, SVG & Markdown",
    matrixScale: "Escala de Matriz",
    grcFramework: "Marco GRC",
    criticals: "Críticos",
    highs: "Altos",
    residual: "Residual",
    welcomeHeading: "Gestión de Riesgo & Impacto",
    welcomeSub:
      "Inicia una nueva auditoría para transformar hallazgos técnicos en matrices de impacto, controles GRC y documentación lista para tu informe final.",
    openSaved: "Abrir proyecto guardado",
    viewDemo: "Ver ejemplo",
    newAudit: "Nueva Auditoría",
    auditName: "Nombre de la auditoría *",
    clientOrg: "Cliente / Organización",
    auditorTeam: "Auditor / Equipo",
    refFramework: "Marco de Referencia",
    createStart: "Crear y comenzar auditoría",
    recentAudits: "Auditorías Recientes",
    noRecent: "Aún no tienes auditorías guardadas",
    noRecentSub:
      "Al crear una auditoría aparecerá aquí automáticamente para retomarla cuando quieras.",
    matrixEyebrow: "Calibración Interactiva · Drag & Drop",
    matrixTitle: "Matriz de Impacto vs. Probabilidad",
    matrixSub:
      "Arrastra cualquier CVE entre celdas para ajustar el riesgo según tu criterio de auditoría, o haz clic en un hallazgo para abrir el inspector.",
    residualEyebrow: "Simulador What-If · Gobernanza",
    residualTitle: "Riesgo Actual vs. Riesgo Residual",
    residualSub:
      "Selecciona hallazgos en el plan de remediación para proyectar cuánto baja el riesgo corporativo.",
    estimatedReduction: "Reducción Estimada",
    currentRisk: "Riesgo Actual",
    residualRisk: "Riesgo Residual (Post-Remediación)",
    prioritizedTitle: "Hallazgos Priorizados & Controles GRC",
    enrichBtn: "Enriquecer CVEs (NVD / EPSS / KEV)",
    enrichingBtn: "Consultando NVD/EPSS/KEV...",
    inspectorTitle: "Inspector de Criterio",
    inspectorEmpty:
      "Selecciona cualquier hallazgo en la matriz o la tabla para revisar la recomendación automática, ajustar el impacto según tu criterio y elegir el control GRC.",
    autoSuggestion: "Sugerencia Automática",
    auditorCriteria: "Criterio del Auditor",
    restore: "Restaurar",
    assignedControl: "Control GRC Asignado",
    reportKitEyebrow: "Paso 05 · Entregables de Documentación",
    reportKitTitle: "Report Kit listo para tu Informe Final",
    saveProject: "Guardar proyecto (.secimpact.json)",
    assetsTab: "Activos",
    findingsTab: "CVEs / Hallazgos",
  },
  en: {
    projects: "Projects",
    settings: "Settings",
    settingsTitle: "SecImpact Settings",
    languageLabel: "Interface Language",
    themeLabel: "Appearance",
    themeDark: "Dark",
    themeLight: "Light",
    close: "Close",
    workflowTitle: "Audit Workflow",
    stepIngest: "Ingest",
    stepIngestSub: "Import findings",
    stepMatrix: "Matrix & Risk",
    stepMatrixSub: "Calibrate & simulate",
    stepZoneMap: "Zone Map",
    stepZoneMapSub: "Internet → DMZ → Internal",
    stepInventory: "Inventory",
    stepInventorySub: "Assets & CVEs",
    stepReport: "Report Kit",
    stepReportSub: "PNG, SVG & Markdown",
    matrixScale: "Matrix Scale",
    grcFramework: "GRC Framework",
    criticals: "Critical",
    highs: "High",
    residual: "Residual",
    welcomeHeading: "Risk & Impact Management",
    welcomeSub:
      "Start a new audit to turn raw technical findings into impact matrices, GRC controls, and executive-ready report deliverables.",
    openSaved: "Open saved project",
    viewDemo: "Load demo",
    newAudit: "New Audit",
    auditName: "Audit name *",
    clientOrg: "Client / Organization",
    auditorTeam: "Auditor / Team",
    refFramework: "Reference Framework",
    createStart: "Create and start audit",
    recentAudits: "Recent Audits",
    noRecent: "No saved audits yet",
    noRecentSub:
      "Once you create an audit it will automatically appear here so you can resume anytime.",
    matrixEyebrow: "Interactive Calibration · Drag & Drop",
    matrixTitle: "Impact vs. Likelihood Matrix",
    matrixSub:
      "Drag any CVE between cells to adjust risk using your auditor judgment, or click a finding to open the right inspector.",
    residualEyebrow: "What-If Simulator · Governance",
    residualTitle: "Current Risk vs. Residual Risk",
    residualSub:
      "Select findings for the remediation plan to project how much organizational risk decreases.",
    estimatedReduction: "Estimated Reduction",
    currentRisk: "Current Risk",
    residualRisk: "Residual Risk (Post-Remediation)",
    prioritizedTitle: "Prioritized Findings & GRC Controls",
    enrichBtn: "Enrich CVEs (NVD / EPSS / KEV)",
    enrichingBtn: "Querying NVD/EPSS/KEV...",
    inspectorTitle: "Auditor Inspector",
    inspectorEmpty:
      "Select any finding in the matrix or table to review the automatic suggestion, calibrate impact/likelihood, and pick its GRC control.",
    autoSuggestion: "Automatic Suggestion",
    auditorCriteria: "Auditor Judgment",
    restore: "Reset",
    assignedControl: "Assigned GRC Control",
    reportKitEyebrow: "Step 05 · Report Deliverables",
    reportKitTitle: "Report Kit ready for your Final Report",
    saveProject: "Save project (.secimpact.json)",
    assetsTab: "Assets",
    findingsTab: "CVEs / Findings",
  },
} as const;

export type TranslationKey = keyof (typeof DICT)["es"];

export function t(lang: Language, key: TranslationKey): string {
  return DICT[lang][key];
}

export function pick(lang: Language, es: string, en: string): string {
  return lang === "en" ? en : es;
}

export function translateSla(lang: Language, sla: string): string {
  if (lang === "es") return sla;
  if (sla.includes("24–72h")) return "Immediate (24–72h)";
  if (sla.includes("7–15")) return "Short-term (7–15 days)";
  if (sla.includes("30")) return "Medium-term (30 days)";
  if (sla.includes("90")) return "Maintenance (90 days)";
  return sla;
}
