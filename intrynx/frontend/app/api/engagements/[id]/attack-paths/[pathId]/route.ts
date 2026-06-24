import { NextResponse } from "next/server";
import { graphStore } from "../../../../../../lib/graph-store";

// GET /engagements/{id}/attack-paths/{pathId}
export async function GET(
  _request: Request,
  { params }: { params: Promise<{ id: string; pathId: string }> }
) {
  const { pathId } = await params;
  const path = graphStore.getPath(pathId);
  if (!path) return NextResponse.json({ error: "Path not found" }, { status: 404 });

  // Annotate each hop with plain-language explanation
  const graph = graphStore.getGraph();
  const nodeMap = new Map(graph.nodes.map((n) => [n.id, n]));

  const hopsExplained = path.nodeIds.map((nid, i) => {
    const node = nodeMap.get(nid);
    const edge = i > 0 ? path.edges[i - 1] : null;
    return {
      hop: i,
      nodeId: nid,
      label: node?.label ?? nid,
      type: node?.type,
      criticality: node?.criticality,
      zone: node?.zone,
      compromised: node?.compromised,
      via: edge ? { relation: edge.relation, technique: edge.technique, ttpId: edge.ttpId } : null,
      explanation: edge
        ? `Moved from ${nodeMap.get(path.nodeIds[i - 1])?.label ?? path.nodeIds[i - 1]} to ${node?.label} via ${edge.technique ?? edge.relation} (${edge.ttpId ?? ""})`
        : `Entry point: ${node?.label}`,
    };
  });

  return NextResponse.json({ path, hopsExplained });
}
