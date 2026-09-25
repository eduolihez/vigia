"use client";

import { Background, Controls, type Edge, type Node, ReactFlow } from "@xyflow/react";
import "@xyflow/react/dist/style.css";
import { useTranslations } from "next-intl";
import { useParams } from "next/navigation";
import { useEffect, useMemo, useState } from "react";
import { ScanSubNav } from "@/components/ScanSubNav";
import { listAssets, listFindings, type AssetOut, type FindingOut } from "@/lib/api";

const ASSET_COLORS: Record<string, string> = {
  domain: "#16a34a",
  subdomain: "#22c55e",
  ip: "#3b82f6",
  service: "#a855f7",
  url: "#eab308",
  email_config: "#ec4899",
};

const FINDING_COLOR = "#ef4444";

function buildGraph(assets: AssetOut[], findings: FindingOut[]): { nodes: Node[]; edges: Edge[] } {
  const nodes: Node[] = [];
  const edges: Edge[] = [];

  // BFS depth from root assets (parent_id === null) so the layout reads top to
  // bottom like the actual discovery hierarchy (domain -> subdomain -> ip/service).
  const depthByAsset = new Map<string, number>();
  const roots = assets.filter((a) => !a.parent_id);
  const queue: [AssetOut, number][] = roots.map((a) => [a, 0]);
  const childrenByParent = new Map<string, AssetOut[]>();
  for (const asset of assets) {
    if (asset.parent_id) {
      const siblings = childrenByParent.get(asset.parent_id) ?? [];
      siblings.push(asset);
      childrenByParent.set(asset.parent_id, siblings);
    }
  }
  while (queue.length > 0) {
    const [asset, depth] = queue.shift()!;
    if (depthByAsset.has(asset.id)) continue;
    depthByAsset.set(asset.id, depth);
    for (const child of childrenByParent.get(asset.id) ?? []) {
      queue.push([child, depth + 1]);
    }
  }
  // Any asset never reached (orphaned parent_id, shouldn't normally happen) still
  // gets placed rather than silently dropped.
  for (const asset of assets) {
    if (!depthByAsset.has(asset.id)) depthByAsset.set(asset.id, 0);
  }

  const countByDepth = new Map<number, number>();
  for (const asset of assets) {
    const depth = depthByAsset.get(asset.id)!;
    const index = countByDepth.get(depth) ?? 0;
    countByDepth.set(depth, index + 1);
    nodes.push({
      id: `asset:${asset.id}`,
      position: { x: index * 220, y: depth * 130 },
      data: { label: `${asset.type}\n${asset.value}` },
      style: {
        background: ASSET_COLORS[asset.type] ?? "#71717a",
        color: "#0a0e14",
        fontSize: 11,
        fontWeight: 600,
        border: "none",
        borderRadius: 6,
        padding: 8,
        whiteSpace: "pre-line",
        width: 180,
      },
    });
    if (asset.parent_id) {
      edges.push({
        id: `e:${asset.parent_id}->${asset.id}`,
        source: `asset:${asset.parent_id}`,
        target: `asset:${asset.id}`,
      });
    }
  }

  const maxDepth = Math.max(0, ...Array.from(depthByAsset.values()));
  const findingDepth = maxDepth + 1;
  findings.forEach((finding, i) => {
    nodes.push({
      id: `finding:${finding.id}`,
      position: { x: i * 220, y: findingDepth * 130 },
      data: { label: `⚠ ${finding.title}` },
      style: {
        background: FINDING_COLOR,
        color: "#fff",
        fontSize: 11,
        fontWeight: 600,
        border: "none",
        borderRadius: 6,
        padding: 8,
        whiteSpace: "pre-line",
        width: 180,
      },
    });
    if (finding.asset_id) {
      edges.push({
        id: `e:${finding.asset_id}->finding:${finding.id}`,
        source: `asset:${finding.asset_id}`,
        target: `finding:${finding.id}`,
        style: { stroke: FINDING_COLOR },
      });
    }
  });

  return { nodes, edges };
}

export default function GraphPage() {
  const t = useTranslations("Graph");
  const params = useParams<{ id: string }>();
  const scanId = params.id;

  const [assets, setAssets] = useState<AssetOut[]>([]);
  const [findings, setFindings] = useState<FindingOut[]>([]);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!scanId) return;
    Promise.all([listAssets(scanId), listFindings(scanId)])
      .then(([a, f]) => {
        setAssets(a);
        setFindings(f);
      })
      .catch((err: Error) => setError(err.message));
  }, [scanId]);

  const { nodes, edges } = useMemo(() => buildGraph(assets, findings), [assets, findings]);

  return (
    <div className="flex flex-col gap-6">
      {scanId && <ScanSubNav scanId={scanId} />}

      <div>
        <h1 className="text-2xl font-semibold tracking-tight text-zinc-50">{t("heading")}</h1>
        <p className="mt-1 text-sm text-zinc-500">{scanId}</p>
      </div>

      {error && (
        <div className="rounded border border-red-500/40 bg-red-500/10 px-4 py-3 text-sm text-red-400">
          {error}
        </div>
      )}

      {nodes.length === 0 ? (
        <p className="text-sm text-zinc-500">{t("empty")}</p>
      ) : (
        <div className="h-[32rem] rounded-lg border border-zinc-800 bg-zinc-950/50">
          <ReactFlow nodes={nodes} edges={edges} fitView colorMode="dark">
            <Background />
            <Controls />
          </ReactFlow>
        </div>
      )}
    </div>
  );
}
