/**
 * Utilidades de seguridad del cliente:
 * - Prevención de Path Traversal en nombres de archivo exportados
 * - Escape XML y sanitización estricta de SVG contra XSS
 */

/**
 * Sanitiza un nombre de archivo eliminando secuencias de Path Traversal (..),
 * separadores de directorio (/ y \), caracteres de control y caracteres
 * reservados de Windows/POSIX.
 */
export function sanitizeFilename(input: string, fallback = "secimpact-export"): string {
  const cleaned = input
    .normalize("NFKD")
    .replace(/[\u0300-\u036f]/g, "") // quitar acentos
    .replace(/\.\.+/g, "-") // eliminar .. (path traversal)
    .replace(/[/\\<>:"|?*\x00-\x1f]/g, "-") // separadores y chars reservados
    .replace(/[^a-zA-Z0-9._-]+/g, "-") // solo caracteres seguros
    .replace(/^[-._]+|[-._]+$/g, "") // sin puntos o guiones al inicio/fin
    .slice(0, 80)
    .toLowerCase();

  return cleaned || fallback;
}

/**
 * Escapa texto arbitrario antes de insertarlo en nodos de texto XML/SVG.
 */
export function escapeXml(input: string): string {
  return String(input)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/**
 * Sanitiza un documento SVG eliminando etiquetas ejecutables (<script>,
 * <foreignObject>, <iframe>, <object>, <embed>) y atributos maliciosos
 * (on*, href/xlink:href con javascript: o data:text/html).
 */
export function sanitizeSvg(rawSvg: string): string {
  if (typeof DOMParser === "undefined") {
    return rawSvg.replace(/<script[\s\S]*?>[\s\S]*?<\/script>/gi, "");
  }

  const parser = new DOMParser();
  const doc = parser.parseFromString(rawSvg, "image/svg+xml");

  const forbiddenTags = ["script", "foreignObject", "iframe", "object", "embed", "link", "meta"];
  for (const tag of forbiddenTags) {
    doc.querySelectorAll(tag).forEach((el) => el.remove());
  }

  doc.querySelectorAll("*").forEach((el) => {
    for (const attr of Array.from(el.attributes)) {
      const name = attr.name.toLowerCase();
      const val = attr.value.trim().toLowerCase();
      if (name.startsWith("on")) {
        el.removeAttribute(attr.name);
      } else if (
        (name === "href" || name === "xlink:href" || name === "src") &&
        (val.startsWith("javascript:") || val.startsWith("data:text/html"))
      ) {
        el.removeAttribute(attr.name);
      }
    }
  });

  return new XMLSerializer().serializeToString(doc.documentElement);
}
