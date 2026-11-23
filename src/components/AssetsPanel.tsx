import { useState } from "react";
import { Plus, Server, Trash2 } from "lucide-react";
import { pick, type Language } from "../i18n";
import type { Asset, AssetType, Exposure } from "../types";

interface AssetsPanelProps {
  lang: Language;
  assets: Asset[];
  onAddAsset: (asset: Asset) => void;
  onDeleteAsset: (id: string) => void;
}

export function AssetsPanel({
  lang,
  assets,
  onAddAsset,
  onDeleteAsset,
}: AssetsPanelProps) {
  const [name, setName] = useState("");
  const [host, setHost] = useState("");
  const [assetType, setAssetType] = useState<AssetType>("server");
  const [exposure, setExposure] = useState<Exposure>("internal");
  const [criticality, setCriticality] = useState(3);
  const [owner, setOwner] = useState("");

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    if (!name.trim()) return;
    onAddAsset({
      id: `asset-${Date.now()}`,
      name: name.trim(),
      host: host.trim() || "N/A",
      assetType,
      exposure,
      criticality,
      owner: owner.trim() || pick(lang, "Sin asignar", "Unassigned"),
    });
    setName("");
    setHost("");
    setOwner("");
  }

  return (
    <div className="grid gap-6 lg:grid-cols-[340px_1fr]">
      <form
        onSubmit={handleSubmit}
        className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5 space-y-4 h-fit"
      >
        <div className="flex items-center gap-2 text-sm font-bold text-[#F2DFC8]">
          <Plus className="h-4 w-4 text-[#F25C2A]" />
          {pick(lang, "Nuevo Activo de Infraestructura", "New Infrastructure Asset")}
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            {pick(lang, "Nombre del activo *", "Asset name *")}
          </label>
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder={pick(lang, "Ej. Servidor ERP Producción", "e.g. Production ERP Server")}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            required
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            IP / Hostname
          </label>
          <input
            value={host}
            onChange={(e) => setHost(e.target.value)}
            placeholder={pick(lang, "Ej. 10.20.5.14 o app.empresa.com", "e.g. 10.20.5.14 or app.company.com")}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className="block text-xs font-medium text-[#8C93A3] mb-1">
              {pick(lang, "Tipo", "Type")}
            </label>
            <select
              value={assetType}
              onChange={(e) => setAssetType(e.target.value as AssetType)}
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-2.5 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            >
              <option value="webApp">{pick(lang, "Aplicación Web", "Web Application")}</option>
              <option value="database">{pick(lang, "Base de Datos", "Database")}</option>
              <option value="server">{pick(lang, "Servidor", "Server")}</option>
              <option value="activeDirectory">Active Directory</option>
              <option value="network">{pick(lang, "Red / Firewall / VPN", "Network / Firewall / VPN")}</option>
              <option value="cloud">Cloud / SaaS</option>
              <option value="workstation">Workstation</option>
            </select>
          </div>

          <div>
            <label className="block text-xs font-medium text-[#8C93A3] mb-1">
              {pick(lang, "Exposición", "Exposure")}
            </label>
            <select
              value={exposure}
              onChange={(e) => setExposure(e.target.value as Exposure)}
              className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-2.5 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
            >
              <option value="internet">{pick(lang, "Internet (Público)", "Internet (Public)")}</option>
              <option value="dmz">DMZ</option>
              <option value="internal">{pick(lang, "Red Interna", "Internal Network")}</option>
            </select>
          </div>
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            {pick(lang, "Criticidad de negocio", "Business criticality")}: <strong className="text-[#F2DFC8]">{criticality}/5</strong>
          </label>
          <input
            type="range"
            min={1}
            max={5}
            value={criticality}
            onChange={(e) => setCriticality(Number(e.target.value))}
            className="w-full accent-[#F25C2A]"
          />
        </div>

        <div>
          <label className="block text-xs font-medium text-[#8C93A3] mb-1">
            {pick(lang, "Responsable / Área", "Owner / Team")}
          </label>
          <input
            value={owner}
            onChange={(e) => setOwner(e.target.value)}
            placeholder={pick(lang, "Ej. Equipo Infraestructura", "e.g. Infrastructure Team")}
            className="w-full rounded-lg border border-[#313644] bg-[#15171D] px-3 py-2 text-xs text-[#E6E1D9] focus:border-[#F25C2A] focus:outline-none"
          />
        </div>

        <button
          type="submit"
          className="w-full rounded-lg bg-[#F25C2A] px-4 py-2 text-xs font-semibold text-white transition hover:bg-[#ff6d3d]"
        >
          {pick(lang, "Agregar Activo", "Add Asset")}
        </button>
      </form>

      <div className="rounded-xl border border-[#2C313E] bg-[#21252F] p-5">
        <h3 className="mb-4 flex items-center gap-2 text-sm font-bold text-[#F2DFC8]">
          <Server className="h-4 w-4 text-[#F25C2A]" />
          {pick(lang, "Inventario de Activos", "Asset Inventory")} ({assets.length})
        </h3>
        <div className="space-y-2">
          {assets.map((asset) => (
            <div
              key={asset.id}
              className="flex items-center justify-between rounded-lg border border-[#2B303D] bg-[#181B22] px-4 py-3"
            >
              <div>
                <p className="text-sm font-semibold text-[#F2DFC8]">{asset.name}</p>
                <p className="text-xs text-[#8C93A3]">
                  {asset.host} ·{" "}
                  <span className="font-mono uppercase text-[#E6E1D9]">{asset.exposure}</span> ·{" "}
                  {pick(lang, "Criticidad", "Criticality")}{" "}
                  <span className="font-mono font-bold text-[#F25C2A]">{asset.criticality}/5</span> ·{" "}
                  {asset.owner}
                </p>
              </div>
              <button
                type="button"
                onClick={() => onDeleteAsset(asset.id)}
                className="rounded-md p-2 text-[#6E7687] transition hover:bg-[#F25C2A]/15 hover:text-[#F25C2A]"
                title={pick(lang, "Eliminar activo", "Delete asset")}
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
