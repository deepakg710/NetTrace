import React, { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import {
  ZoomIn,
  ZoomOut,
  Maximize2,
  Crosshair,
} from 'lucide-react';
import { TopologyEdge, TopologyNode } from '../../types';

export const SEV_COLORS: Record<string, string> = {
  Critical: '#ef4444',
  High: '#f43f5e',
  Medium: '#f59e0b',
  Low: '#06b6d4',
  Informational: '#3b82f6',
};

export interface TopologyGraphProps {
  nodes: TopologyNode[];
  edges: TopologyEdge[];
  layoutMode: 'force' | 'grouped';
  selectedNodeId: string | null;
  selectedEdgeId: string | null;
  highlightedNodeIds?: Set<string>;
  highlightedEdgeIds?: Set<string>;
  searchQuery?: string;
  captureFilename?: string;
  totalFlowsCount?: number;
  onSelectNode: (node: TopologyNode | null) => void;
  onSelectEdge: (edge: TopologyEdge | null) => void;
  resetSignal: number;
  fitViewSignal?: number;
}

interface PositionedNode {
  node: TopologyNode;
  x: number;
  y: number;
  radius: number;
  isIsolated: boolean;
}

const formatBytesShort = (bytes: number): string => {
  if (bytes <= 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(sizes.length - 1, Math.floor(Math.log(bytes) / Math.log(k)));
  const val = bytes / Math.pow(k, i);
  return `${val >= 10 || i === 0 ? Math.round(val) : val.toFixed(1)} ${sizes[i]}`;
};

/**
 * Deterministic layout generator that prevents node/label overlap,
 * separates isolated endpoints cleanly into a dedicated bottom-right zone,
 * and balances connected nodes across the available canvas viewport.
 */
function computeDeterministicLayout(
  nodes: TopologyNode[],
  edges: TopologyEdge[],
  layoutMode: 'force' | 'grouped',
  width: number,
  height: number,
  maxNodeBytes: number
): Map<string, { x: number; y: number; radius: number; isIsolated: boolean }> {
  const result = new Map<string, { x: number; y: number; radius: number; isIsolated: boolean }>();
  const nCount = nodes.length;
  if (nCount === 0) return result;

  const padX = Math.max(95, Math.min(140, width * 0.13));
  const padY = Math.max(72, Math.min(100, height * 0.14));
  const usableW = Math.max(260, width - padX * 2);
  const usableH = Math.max(220, height - padY * 2);
  const centerX = width / 2;
  const centerY = height / 2 - 12;

  const getRadius = (n: TopologyNode): number => {
    const ratio = maxNodeBytes > 0 ? Math.max(0, n.bytes) / maxNodeBytes : 0;
    return Math.round(22 + 12 * Math.sqrt(ratio));
  };

  // Degree map for deterministic sorting and isolated detection
  const degreeMap = new Map<string, number>();
  for (const n of nodes) {
    degreeMap.set(n.id, 0);
  }
  for (const e of edges) {
    if (degreeMap.has(e.source) && degreeMap.has(e.target)) {
      degreeMap.set(e.source, (degreeMap.get(e.source) || 0) + 1);
      degreeMap.set(e.target, (degreeMap.get(e.target) || 0) + 1);
    }
  }

  const sortedNodes = [...nodes].sort((a, b) => {
    const degDiff = (degreeMap.get(b.id) || 0) - (degreeMap.get(a.id) || 0);
    if (degDiff !== 0) return degDiff;
    if (b.bytes !== a.bytes) return b.bytes - a.bytes;
    return a.id.localeCompare(b.id);
  });

  if (layoutMode === 'grouped') {
    // Group into up to 3 balanced functional columns:
    // Col 0: Local Clients / Workstations / Scanners
    // Col 1: Servers / DNS / Gateways / Targets
    // Col 2: Remote / Public / Multicast / Isolated
    const col0: TopologyNode[] = [];
    const col1: TopologyNode[] = [];
    const col2: TopologyNode[] = [];

    for (const n of sortedNodes) {
      const roleSet = new Set(n.roles.map((r) => r.role));
      if (n.kind === 'inferred_gateway' || roleSet.has('gateway')) {
        col1.push(n);
      } else if (n.scope === 'remote' || n.scope === 'multicast') {
        col2.push(n);
      } else if (roleSet.has('dns_server') || roleSet.has('scan_target')) {
        col1.push(n);
      } else {
        col0.push(n);
      }
    }

    const nonEmptyCols = [col0, col1, col2].filter((c) => c.length > 0);
    if (nonEmptyCols.length === 1 && nonEmptyCols[0].length > 2) {
      const all = nonEmptyCols[0];
      const half = Math.ceil(all.length / 2);
      nonEmptyCols.splice(0, 1, all.slice(0, half), all.slice(half));
    }

    const colCount = nonEmptyCols.length;
    nonEmptyCols.forEach((colNodes, cIdx) => {
      const colX =
        colCount === 1
          ? centerX
          : padX + (cIdx / (colCount - 1)) * usableW;

      const countInCol = colNodes.length;
      colNodes.forEach((n, rIdx) => {
        const yFrac = countInCol === 1 ? 0.5 : rIdx / (countInCol - 1);
        const staggerX = countInCol > 2 ? (rIdx % 2 === 0 ? -20 : 20) : 0;
        const x = colX + staggerX;
        const y = padY + 12 + yFrac * (usableH - 18);
        const isIso = (degreeMap.get(n.id) || 0) === 0;
        result.set(n.id, { x, y, radius: getRadius(n), isIsolated: isIso });
      });
    });

    return result;
  }

  // FORCE-DIRECTED (Deterministic Fruchterman-Reingold + Bounding-Box Collision Avoidance)
  if (nCount === 1) {
    const only = sortedNodes[0];
    result.set(only.id, {
      x: centerX,
      y: centerY,
      radius: getRadius(only),
      isIsolated: (degreeMap.get(only.id) || 0) === 0,
    });
    return result;
  }

  const pos = new Map<
    string,
    { x: number; y: number; vx: number; vy: number; radius: number; isIsolated: boolean }
  >();

  // Separate connected nodes from isolated nodes
  const connected = sortedNodes.filter((n) => (degreeMap.get(n.id) || 0) > 0);
  const isolated = sortedNodes.filter((n) => (degreeMap.get(n.id) || 0) === 0);

  const mainNodes = connected.length > 0 ? connected : isolated;
  const mCount = mainNodes.length;

  mainNodes.forEach((n, idx) => {
    const r = getRadius(n);
    const isIso = (degreeMap.get(n.id) || 0) === 0;
    if (
      idx === 0 &&
      mCount >= 5 &&
      (degreeMap.get(n.id) || 0) >= Math.ceil((mCount - 1) * 0.6)
    ) {
      pos.set(n.id, { x: centerX, y: centerY, vx: 0, vy: 0, radius: r, isIsolated: isIso });
    } else {
      const angle = -Math.PI * 0.65 + (2 * Math.PI * idx) / mCount;
      const rx = usableW * 0.38;
      const ry = usableH * 0.38;
      pos.set(n.id, {
        x: centerX + rx * Math.cos(angle),
        y: centerY + ry * Math.sin(angle),
        vx: 0,
        vy: 0,
        radius: r,
        isIsolated: isIso,
      });
    }
  });

  const idealLen = Math.max(
    155,
    Math.min(245, Math.sqrt((usableW * usableH) / Math.max(2, mCount)) * 0.88)
  );
  const iterations = 170;

  for (let iter = 0; iter < iterations; iter++) {
    const temp = (1 - iter / iterations) * 18;
    const nodeEntries = Array.from(pos.entries());

    // 1. Repulsive forces between all connected pairs
    for (let i = 0; i < nodeEntries.length; i++) {
      const [, pA] = nodeEntries[i];
      for (let j = i + 1; j < nodeEntries.length; j++) {
        const [, pB] = nodeEntries[j];
        const dx = pA.x - pB.x;
        const dy = pA.y - pB.y;
        const distSq = dx * dx + (dy * 1.25) * (dy * 1.25) + 0.01;
        const dist = Math.sqrt(distSq);
        const repulse = (idealLen * idealLen * 1.38) / dist;
        const fx = (dx / dist) * repulse;
        const fy = (dy / dist) * repulse;
        pA.vx += fx;
        pA.vy += fy;
        pB.vx -= fx;
        pB.vy -= fy;
      }
    }

    // 2. Attractive forces along edges
    for (const e of edges) {
      const pS = pos.get(e.source);
      const pT = pos.get(e.target);
      if (!pS || !pT) continue;
      const dx = pT.x - pS.x;
      const dy = pT.y - pS.y;
      const dist = Math.max(1, Math.sqrt(dx * dx + dy * dy));
      const attract = ((dist - idealLen) * dist) / (idealLen * 2.15);
      const fx = (dx / dist) * attract;
      const fy = (dy / dist) * attract;
      pS.vx += fx;
      pS.vy += fy;
      pT.vx -= fx;
      pT.vy -= fy;
    }

    // 3. Gentle centering gravity
    for (const [, p] of nodeEntries) {
      p.vx += (centerX - p.x) * 0.04;
      p.vy += (centerY - p.y) * 0.04;

      const vMag = Math.max(0.1, Math.sqrt(p.vx * p.vx + p.vy * p.vy));
      const step = Math.min(temp, vMag);
      p.x += (p.vx / vMag) * step;
      p.y += (p.vy / vMag) * step;
      p.vx = 0;
      p.vy = 0;
    }
  }

  // 4. Normalize connected nodes to fill the usable canvas nicely
  if (pos.size > 1) {
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const [, p] of pos) {
      if (p.x < minX) minX = p.x;
      if (p.x > maxX) maxX = p.x;
      if (p.y < minY) minY = p.y;
      if (p.y > maxY) maxY = p.y;
    }
    const spanX = Math.max(1, maxX - minX);
    const spanY = Math.max(1, maxY - minY);
    const targetH = isolated.length > 0 ? usableH * 0.74 : usableH * 0.86;
    const targetW = isolated.length > 0 ? usableW * 0.82 : usableW * 0.88;
    const offsetCenterX = isolated.length > 0 ? centerX - 24 : centerX;
    const offsetCenterY = isolated.length > 0 ? centerY - 22 : centerY;

    for (const [, p] of pos) {
      p.x = offsetCenterX + ((p.x - (minX + maxX) / 2) / spanX) * targetW;
      p.y = offsetCenterY + ((p.y - (minY + maxY) / 2) / spanY) * targetH;
    }
  }

  // 5. Place isolated nodes (if any) in a dedicated bottom-right zone (matching reference image)
  if (connected.length > 0 && isolated.length > 0) {
    const isoCount = isolated.length;
    isolated.forEach((n, idx) => {
      // Arrange isolated endpoints from right-to-left along the bottom-right margin
      const col = idx % 4;
      const row = Math.floor(idx / 4);
      const isoX =
        isoCount === 1
          ? width - padX * 0.95
          : width - padX * 0.85 - col * 142;
      const isoY = height - padY * 0.78 - row * 105;
      pos.set(n.id, {
        x: Math.max(padX, isoX),
        y: Math.max(padY, isoY),
        vx: 0,
        vy: 0,
        radius: getRadius(n),
        isIsolated: true,
      });
    });
  }

  // 6. Explicit Node + Label Bounding-Box Collision Resolution Pass
  const minSepX = nCount <= 12 ? 152 : nCount <= 25 ? 118 : 88;
  const minSepY = nCount <= 12 ? 120 : nCount <= 25 ? 96 : 74;
  const allEntries = Array.from(pos.entries());

  for (let pass = 0; pass < 45; pass++) {
    let moved = false;
    for (let i = 0; i < allEntries.length; i++) {
      const [, pA] = allEntries[i];
      for (let j = i + 1; j < allEntries.length; j++) {
        const [, pB] = allEntries[j];
        const dx = pB.x - pA.x;
        const dy = pB.y - pA.y;
        const overlapX = minSepX - Math.abs(dx);
        const overlapY = minSepY - Math.abs(dy);
        if (overlapX > 0 && overlapY > 0) {
          moved = true;
          if (overlapX < overlapY) {
            const push = (overlapX / 2 + 2) * (dx >= 0 ? 1 : -1);
            pA.x -= push;
            pB.x += push;
          } else {
            const push = (overlapY / 2 + 2) * (dy >= 0 ? 1 : -1);
            pA.y -= push;
            pB.y += push;
          }
        }
      }
    }
    for (const [, p] of allEntries) {
      p.x = Math.max(padX * 0.72, Math.min(width - padX * 0.72, p.x));
      p.y = Math.max(padY * 0.65, Math.min(height - padY * 0.82, p.y));
    }
    if (!moved) break;
  }

  for (const [id, p] of pos) {
    result.set(id, { x: p.x, y: p.y, radius: p.radius, isIsolated: p.isIsolated });
  }
  return result;
}

export const TopologyGraph: React.FC<TopologyGraphProps> = ({
  nodes,
  edges,
  layoutMode,
  selectedNodeId,
  selectedEdgeId,
  highlightedNodeIds,
  highlightedEdgeIds,
  searchQuery = '',
  captureFilename = '',
  totalFlowsCount,
  onSelectNode,
  onSelectEdge,
  resetSignal,
  fitViewSignal = 0,
}) => {
  const containerRef = useRef<HTMLDivElement | null>(null);
  const [dimensions, setDimensions] = useState<{ width: number; height: number }>({
    width: 820,
    height: 540,
  });

  // Camera transform state (pan & zoom)
  const [transform, setTransform] = useState<{ x: number; y: number; k: number }>({
    x: 0,
    y: 0,
    k: 1,
  });

  // User manual drag overrides for node coordinates
  const [dragOverrides, setDragOverrides] = useState<Map<string, { x: number; y: number }>>(
    () => new Map()
  );

  // Active interaction state
  const [draggingNodeId, setDraggingNodeId] = useState<string | null>(null);
  const [isPanning, setIsPanning] = useState<boolean>(false);
  const panStartRef = useRef<{ clientX: number; clientY: number; tx: number; ty: number } | null>(
    null
  );
  const dragMovedRef = useRef<boolean>(false);

  const [hoveredNode, setHoveredNode] = useState<TopologyNode | null>(null);
  const [hoveredEdge, setHoveredEdge] = useState<TopologyEdge | null>(null);

  useEffect(() => {
    const el = containerRef.current;
    if (!el) return;
    const updateSize = () => {
      const rect = el.getBoundingClientRect();
      if (rect.width > 0 && rect.height > 0) {
        setDimensions({
          width: Math.floor(rect.width),
          height: Math.floor(rect.height),
        });
      }
    };
    updateSize();
    if (typeof ResizeObserver !== 'undefined') {
      const ro = new ResizeObserver(updateSize);
      ro.observe(el);
      return () => ro.disconnect();
    }
    window.addEventListener('resize', updateSize);
    return () => window.removeEventListener('resize', updateSize);
  }, []);

  const maxNodeBytes = useMemo(() => {
    let maxB = 1;
    for (const n of nodes) {
      if (n.bytes > maxB) maxB = n.bytes;
    }
    return maxB;
  }, [nodes]);

  const maxEdgeBytes = useMemo(() => {
    let maxB = 1;
    for (const e of edges) {
      if (e.bytes > maxB) maxB = e.bytes;
    }
    return maxB;
  }, [edges]);

  const basePositions = useMemo(
    () =>
      computeDeterministicLayout(
        nodes,
        edges,
        layoutMode,
        dimensions.width,
        dimensions.height,
        maxNodeBytes
      ),
    [nodes, edges, layoutMode, dimensions.width, dimensions.height, maxNodeBytes]
  );

  const positionedNodes: PositionedNode[] = useMemo(() => {
    return nodes.map((n) => {
      const base = basePositions.get(n.id) || {
        x: dimensions.width / 2,
        y: dimensions.height / 2,
        radius: 24,
        isIsolated: false,
      };
      const override = dragOverrides.get(n.id);
      return {
        node: n,
        x: override ? override.x : base.x,
        y: override ? override.y : base.y,
        radius: base.radius,
        isIsolated: base.isIsolated,
      };
    });
  }, [nodes, basePositions, dragOverrides, dimensions.width, dimensions.height]);

  const posById = useMemo(() => {
    const map = new Map<string, PositionedNode>();
    for (const pn of positionedNodes) {
      map.set(pn.node.id, pn);
    }
    return map;
  }, [positionedNodes]);

  // Fit all visible nodes into the viewport
  const fitToView = useCallback(() => {
    if (positionedNodes.length === 0) {
      setTransform({ x: 0, y: 0, k: 1 });
      return;
    }
    let minX = Infinity;
    let maxX = -Infinity;
    let minY = Infinity;
    let maxY = -Infinity;
    for (const pn of positionedNodes) {
      minX = Math.min(minX, pn.x - pn.radius - 55);
      maxX = Math.max(maxX, pn.x + pn.radius + 55);
      minY = Math.min(minY, pn.y - pn.radius - 35);
      maxY = Math.max(maxY, pn.y + pn.radius + 60);
    }
    const contentW = Math.max(120, maxX - minX);
    const contentH = Math.max(120, maxY - minY);
    const scaleX = (dimensions.width - 40) / contentW;
    const scaleY = (dimensions.height - 40) / contentH;
    const k = Math.max(0.45, Math.min(1.35, Math.min(scaleX, scaleY)));
    const cx = (minX + maxX) / 2;
    const cy = (minY + maxY) / 2;
    setTransform({
      x: dimensions.width / 2 - cx * k,
      y: dimensions.height / 2 - cy * k,
      k,
    });
  }, [positionedNodes, dimensions.width, dimensions.height]);

  const centerOnSelectedNode = useCallback(() => {
    if (!selectedNodeId) {
      fitToView();
      return;
    }
    const target = posById.get(selectedNodeId);
    if (!target) {
      fitToView();
      return;
    }
    const nextK = Math.max(1, Math.min(1.4, transform.k));
    setTransform({
      x: dimensions.width / 2 - target.x * nextK,
      y: dimensions.height / 2 - target.y * nextK,
      k: nextK,
    });
  }, [selectedNodeId, posById, fitToView, transform.k, dimensions.width, dimensions.height]);

  // Reset layout clears drag overrides and resets camera
  useEffect(() => {
    setDragOverrides(new Map());
    setTransform({ x: 0, y: 0, k: 1 });
  }, [resetSignal, layoutMode]);

  useEffect(() => {
    if (fitViewSignal > 0) {
      fitToView();
    }
  }, [fitViewSignal, fitToView]);

  // Search query matching
  const normalizedQuery = searchQuery.trim().toLowerCase();
  const searchMatchedNodeIds = useMemo(() => {
    const set = new Set<string>();
    if (!normalizedQuery) return set;
    for (const n of nodes) {
      const matchId = n.id.toLowerCase().includes(normalizedQuery);
      const matchClass = (n.classification || '').toLowerCase().includes(normalizedQuery);
      const matchRole = n.roles.some((r) => r.role.toLowerCase().includes(normalizedQuery));
      const matchMac = n.macs.some((m) => m.toLowerCase().includes(normalizedQuery));
      if (matchId || matchClass || matchRole || matchMac) {
        set.add(n.id);
      }
    }
    return set;
  }, [nodes, normalizedQuery]);

  // Determine if a highlight filter is active (from search, finding selection, or node/edge selection)
  const activeHighlightNodes = useMemo(() => {
    if (normalizedQuery && searchMatchedNodeIds.size > 0) {
      return searchMatchedNodeIds;
    }
    if (highlightedNodeIds && highlightedNodeIds.size > 0) {
      return highlightedNodeIds;
    }
    if (selectedNodeId) {
      const peerSet = new Set<string>([selectedNodeId]);
      for (const e of edges) {
        if (e.source === selectedNodeId) peerSet.add(e.target);
        if (e.target === selectedNodeId) peerSet.add(e.source);
      }
      return peerSet;
    }
    if (selectedEdgeId) {
      const edge = edges.find((e) => e.id === selectedEdgeId);
      if (edge) return new Set<string>([edge.source, edge.target]);
    }
    return null;
  }, [
    normalizedQuery,
    searchMatchedNodeIds,
    highlightedNodeIds,
    selectedNodeId,
    selectedEdgeId,
    edges,
  ]);

  const getNodeRingColor = (node: TopologyNode, isIsolated: boolean): string => {
    if (node.finding_ids.length > 0 && node.max_severity) {
      if (node.max_severity === 'Critical' || node.max_severity === 'High') return '#f43f5e';
      if (node.max_severity === 'Medium') return '#f59e0b';
    }
    const roleNames = new Set(node.roles.map((r) => r.role));
    if (node.kind === 'inferred_gateway' || roleNames.has('gateway')) return '#f59e0b';
    if (roleNames.has('scanner')) return '#f43f5e';
    if (roleNames.has('dns_server')) return '#10b981';
    if (roleNames.has('scan_target')) return '#f59e0b';
    if (isIsolated) return '#64748b';
    if (node.scope === 'remote') return '#a855f7';
    if (node.scope === 'local') return '#0ea5e9';
    return '#64748b';
  };

  const getEdgeColor = (edge: TopologyEdge): string => {
    if (edge.status === 'reset') return '#f43f5e';
    if (edge.status === 'incomplete') return '#f59e0b';
    if (edge.status === 'scan') return '#a855f7';
    if (edge.kind === 'inferred_l2' || edge.inferred) return '#10b981';
    const protos = edge.protocols.map((p) => p.toUpperCase());
    if (protos.includes('DNS')) return '#10b981';
    if (protos.includes('UDP') && !protos.includes('TCP')) return '#a855f7';
    return '#3b82f6';
  };

  const getEdgeMarkerId = (edge: TopologyEdge, isSelected: boolean): string => {
    if (isSelected) return 'arrow-selected';
    if (edge.status === 'reset') return 'arrow-reset';
    if (edge.status === 'incomplete') return 'arrow-incomplete';
    if (edge.status === 'scan') return 'arrow-scan';
    if (edge.kind === 'inferred_l2' || edge.inferred) return 'arrow-inferred';
    const protos = edge.protocols.map((p) => p.toUpperCase());
    if (protos.includes('DNS')) return 'arrow-dns';
    if (protos.includes('UDP') && !protos.includes('TCP')) return 'arrow-udp';
    return 'arrow-tcp';
  };

  const getEdgeStrokeWidth = (edge: TopologyEdge, isSelected: boolean): number => {
    if (edge.kind === 'inferred_l2' || edge.inferred) return isSelected ? 2.5 : 1.5;
    const ratio = maxEdgeBytes > 0 ? Math.max(0, edge.bytes) / maxEdgeBytes : 0;
    const base = 1.6 + 3.4 * Math.sqrt(ratio);
    return isSelected ? base + 1.4 : base;
  };

  // Precompute non-overlapping mid-edge label positions so edge labels never collide with nodes or each other
  const edgeGeometries = useMemo(() => {
    const placedLabels: Array<{ x: number; y: number }> = [];
    // Seed with node positions and node label boxes so edge labels avoid nodes
    for (const pn of positionedNodes) {
      placedLabels.push({ x: pn.x, y: pn.y });
      placedLabels.push({ x: pn.x, y: pn.y + pn.radius + 16 });
    }

    return edges.map((edge, idx) => {
      const fromIp = edge.initiator || edge.source;
      const toIp = edge.responder || (fromIp === edge.source ? edge.target : edge.source);
      const pFrom = posById.get(fromIp) || posById.get(edge.source);
      const pTo = posById.get(toIp) || posById.get(edge.target);
      if (!pFrom || !pTo) return null;

      const dx = pTo.x - pFrom.x;
      const dy = pTo.y - pFrom.y;
      const dist = Math.max(1, Math.hypot(dx, dy));
      const ux = dx / dist;
      const uy = dy / dist;

      const curveSign = idx % 2 === 0 ? 1 : -1;
      const curveOffset = Math.min(36, dist * 0.13) * curveSign;
      const nx = -uy;
      const ny = ux;
      const ctrlX = (pFrom.x + pTo.x) / 2 + nx * curveOffset;
      const ctrlY = (pFrom.y + pTo.y) / 2 + ny * curveOffset;

      const startPad = pFrom.radius + 5;
      const endPad = pTo.radius + 7;
      const startX = pFrom.x + ux * startPad;
      const startY = pFrom.y + uy * startPad;
      const endX = pTo.x - ux * endPad;
      const endY = pTo.y - uy * endPad;

      // Candidate parameter values along the quadratic Bezier curve
      const candidates = [0.5, 0.38, 0.62, 0.3, 0.7];
      let bestX = 0.25 * startX + 0.5 * ctrlX + 0.25 * endX;
      let bestY = 0.25 * startY + 0.5 * ctrlY + 0.25 * endY;

      for (const t of candidates) {
        const mt = 1 - t;
        const cx = mt * mt * startX + 2 * mt * t * ctrlX + t * t * endX;
        const cy = mt * mt * startY + 2 * mt * t * ctrlY + t * t * endY;
        const collides = placedLabels.some(
          (pl) => Math.abs(pl.x - cx) < 62 && Math.abs(pl.y - cy) < 28
        );
        if (!collides) {
          bestX = cx;
          bestY = cy;
          break;
        }
      }
      placedLabels.push({ x: bestX, y: bestY });

      return {
        edge,
        startX,
        startY,
        ctrlX,
        ctrlY,
        endX,
        endY,
        labelX: bestX,
        labelY: bestY,
        dist,
      };
    });
  }, [edges, posById, positionedNodes]);

  // Mouse handlers for canvas pan and node dragging
  const handleWheel = (e: React.WheelEvent<SVGSVGElement>) => {
    e.preventDefault();
    const factor = e.deltaY < 0 ? 1.12 : 0.89;
    const nextK = Math.max(0.35, Math.min(2.75, transform.k * factor));
    const rect = e.currentTarget.getBoundingClientRect();
    const mx = e.clientX - rect.left;
    const my = e.clientY - rect.top;
    setTransform((prev) => ({
      k: nextK,
      x: mx - ((mx - prev.x) / prev.k) * nextK,
      y: my - ((my - prev.y) / prev.k) * nextK,
    }));
  };

  const handleSvgMouseDown = (e: React.MouseEvent<SVGSVGElement>) => {
    if (e.button !== 0) return;
    setIsPanning(true);
    dragMovedRef.current = false;
    panStartRef.current = {
      clientX: e.clientX,
      clientY: e.clientY,
      tx: transform.x,
      ty: transform.y,
    };
  };

  const handleSvgMouseMove = (e: React.MouseEvent<SVGSVGElement>) => {
    if (draggingNodeId) {
      dragMovedRef.current = true;
      const rect = e.currentTarget.getBoundingClientRect();
      const worldX = (e.clientX - rect.left - transform.x) / transform.k;
      const worldY = (e.clientY - rect.top - transform.y) / transform.k;
      setDragOverrides((prev) => {
        const next = new Map(prev);
        next.set(draggingNodeId, { x: worldX, y: worldY });
        return next;
      });
      return;
    }
    if (isPanning && panStartRef.current) {
      const dx = e.clientX - panStartRef.current.clientX;
      const dy = e.clientY - panStartRef.current.clientY;
      if (Math.abs(dx) > 3 || Math.abs(dy) > 3) {
        dragMovedRef.current = true;
      }
      setTransform((prev) => ({
        ...prev,
        x: (panStartRef.current?.tx ?? 0) + dx,
        y: (panStartRef.current?.ty ?? 0) + dy,
      }));
    }
  };

  const handleSvgMouseUp = () => {
    setDraggingNodeId(null);
    setIsPanning(false);
    panStartRef.current = null;
  };

  const renderNodeIcon = (node: TopologyNode, isIsolated: boolean) => {
    const roleSet = new Set(node.roles.map((r) => r.role));
    const color = getNodeRingColor(node, isIsolated);

    // Gateway / Router icon
    if (node.kind === 'inferred_gateway' || roleSet.has('gateway')) {
      return (
        <g stroke={color} strokeWidth="1.8" fill="none" strokeLinecap="round" strokeLinejoin="round">
          <rect x="-10" y="-4" width="20" height="9" rx="2" />
          <line x1="-6" y1="-4" x2="-6" y2="-9" />
          <line x1="6" y1="-4" x2="6" y2="-9" />
          <circle cx="-5" cy="0.5" r="1" fill={color} />
          <circle cx="0" cy="0.5" r="1" fill={color} />
        </g>
      );
    }

    // Remote / Globe icon
    if (node.scope === 'remote') {
      return (
        <g stroke={color} strokeWidth="1.7" fill="none" strokeLinecap="round" strokeLinejoin="round">
          <circle cx="0" cy="0" r="10" />
          <line x1="-10" y1="0" x2="10" y2="0" />
          <path d="M 0 -10 C 3.5 -6.5 3.5 6.5 0 10 C -3.5 6.5 -3.5 -6.5 0 -10 Z" />
        </g>
      );
    }

    // Server / DNS Server / Scan Target icon
    if (roleSet.has('dns_server') || roleSet.has('scan_target')) {
      return (
        <g stroke={color} strokeWidth="1.7" fill="none" strokeLinecap="round" strokeLinejoin="round">
          <rect x="-9" y="-8" width="18" height="6.5" rx="1.5" />
          <rect x="-9" y="1.5" width="18" height="6.5" rx="1.5" />
          <circle cx="-5" cy="-4.75" r="0.9" fill={color} />
          <circle cx="-5" cy="4.75" r="0.9" fill={color} />
          <line x1="2" y1="-4.75" x2="6" y2="-4.75" />
          <line x1="2" y1="4.75" x2="6" y2="4.75" />
        </g>
      );
    }

    // Default Host / Workstation Laptop/Monitor icon
    return (
      <g stroke={color} strokeWidth="1.7" fill="none" strokeLinecap="round" strokeLinejoin="round">
        <rect x="-9.5" y="-7.5" width="19" height="12" rx="2" />
        <line x1="-6.5" y1="7.5" x2="6.5" y2="7.5" />
        <line x1="0" y1="4.5" x2="0" y2="7.5" />
      </g>
    );
  };

  const showAllLabels = nodes.length <= 32 || transform.k >= 0.9;
  const totalObservedFlows =
    totalFlowsCount ?? edges.reduce((acc, e) => acc + (e.flow_count || 0), 0);

  return (
    <div
      ref={containerRef}
      className="w-full h-full min-h-[420px] bg-[#040917] rounded-xl border border-slate-800/90 overflow-hidden relative select-none"
      data-testid="topology-canvas-wrapper"
    >
      {/* Subtle radial dot & atmosphere background matching reference */}
      <div
        className="absolute inset-0 pointer-events-none"
        style={{
          backgroundImage:
            'radial-gradient(circle at 50% 45%, rgba(14, 165, 233, 0.07) 0%, rgba(2, 6, 23, 0) 70%), radial-gradient(rgba(51, 65, 85, 0.32) 1px, transparent 1px)',
          backgroundSize: '100% 100%, 24px 24px',
        }}
      />

      {/* Interactive SVG Topology Surface */}
      <svg
        width={dimensions.width}
        height={dimensions.height}
        className={`w-full h-full block ${
          draggingNodeId ? 'cursor-grabbing' : isPanning ? 'cursor-grabbing' : 'cursor-grab'
        }`}
        onWheel={handleWheel}
        onMouseDown={handleSvgMouseDown}
        onMouseMove={handleSvgMouseMove}
        onMouseUp={handleSvgMouseUp}
        onMouseLeave={handleSvgMouseUp}
        onClick={() => {
          if (!dragMovedRef.current) {
            onSelectNode(null);
            onSelectEdge(null);
          }
        }}
      >
        <defs>
          {[
            { id: 'arrow-tcp', color: '#3b82f6' },
            { id: 'arrow-dns', color: '#10b981' },
            { id: 'arrow-udp', color: '#a855f7' },
            { id: 'arrow-reset', color: '#f43f5e' },
            { id: 'arrow-incomplete', color: '#f59e0b' },
            { id: 'arrow-scan', color: '#a855f7' },
            { id: 'arrow-inferred', color: '#10b981' },
            { id: 'arrow-selected', color: '#22d3ee' },
          ].map((m) => (
            <marker
              key={m.id}
              id={m.id}
              viewBox="0 0 10 10"
              refX="8.5"
              refY="5"
              markerWidth="6"
              markerHeight="6"
              orient="auto-start-reverse"
            >
              <path d="M 0 1.5 L 9 5 L 0 8.5 z" fill={m.color} />
            </marker>
          ))}
        </defs>

        <g transform={`translate(${transform.x}, ${transform.y}) scale(${transform.k})`}>
          {/* Grouped Layout Column Headers */}
          {layoutMode === 'grouped' && nodes.length > 0 && (
            <g className="pointer-events-none">
              <text
                x={Math.max(95, dimensions.width * 0.13)}
                y={28}
                textAnchor="middle"
                fill="#64748b"
                fontSize="10"
                fontWeight="600"
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                LOCAL HOSTS &amp; CLIENTS
              </text>
              <text
                x={dimensions.width / 2}
                y={28}
                textAnchor="middle"
                fill="#64748b"
                fontSize="10"
                fontWeight="600"
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                SERVICES &amp; GATEWAYS
              </text>
              <text
                x={dimensions.width - Math.max(95, dimensions.width * 0.13)}
                y={28}
                textAnchor="middle"
                fill="#64748b"
                fontSize="10"
                fontWeight="600"
                fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
              >
                REMOTE / EXTERNAL
              </text>
            </g>
          )}

          {/* Edges Layer */}
          {edgeGeometries.map((geom) => {
            if (!geom) return null;
            const { edge, startX, startY, ctrlX, ctrlY, endX, endY, labelX, labelY, dist } = geom;

            const isSelected = edge.id === selectedEdgeId;
            const isHovered = hoveredEdge?.id === edge.id;
            const isHighlighted =
              !activeHighlightNodes ||
              (highlightedEdgeIds && highlightedEdgeIds.size > 0
                ? highlightedEdgeIds.has(edge.id)
                : activeHighlightNodes.has(edge.source) && activeHighlightNodes.has(edge.target));

            const strokeColor = isSelected || isHovered ? '#22d3ee' : getEdgeColor(edge);
            const strokeW = getEdgeStrokeWidth(edge, isSelected || isHovered);
            const markerId = getEdgeMarkerId(edge, isSelected || isHovered);
            const isInferred = edge.kind === 'inferred_l2' || Boolean(edge.inferred);

            const protoLabel =
              edge.protocols.length > 0
                ? edge.protocols.slice(0, 2).join('/')
                : isInferred
                ? 'L2 Link'
                : 'IP';
            const subLabel = isInferred ? '(inferred)' : formatBytesShort(edge.bytes);

            const showEdgeLabel =
              showAllLabels || isSelected || isHovered || edge.finding_ids.length > 0;

            return (
              <g
                key={edge.id}
                opacity={isHighlighted ? 1 : 0.2}
                className="transition-opacity duration-150 cursor-pointer"
                onMouseEnter={() => setHoveredEdge(edge)}
                onMouseLeave={() => setHoveredEdge(null)}
                onClick={(e) => {
                  e.stopPropagation();
                  onSelectNode(null);
                  onSelectEdge(edge);
                }}
              >
                {/* Invisible wider hit path for effortless clicking */}
                <path
                  d={`M ${startX} ${startY} Q ${ctrlX} ${ctrlY} ${endX} ${endY}`}
                  fill="none"
                  stroke="transparent"
                  strokeWidth={14}
                />

                {/* Visible directional curve */}
                <path
                  d={`M ${startX} ${startY} Q ${ctrlX} ${ctrlY} ${endX} ${endY}`}
                  fill="none"
                  stroke={strokeColor}
                  strokeWidth={strokeW}
                  strokeDasharray={isInferred ? '6 4' : undefined}
                  markerEnd={`url(#${markerId})`}
                  markerStart={edge.bidirectional ? `url(#${markerId})` : undefined}
                />

                {/* Collision-avoidant mid-edge protocol & byte volume pill */}
                {showEdgeLabel && dist > 88 && (
                  <g transform={`translate(${labelX}, ${labelY})`}>
                    <rect
                      x={-34}
                      y={-13}
                      width={68}
                      height={24}
                      rx={5}
                      fill="#040917"
                      fillOpacity={0.92}
                      stroke={isSelected ? '#22d3ee' : '#1e293b'}
                      strokeWidth={0.9}
                    />
                    <text
                      x={0}
                      y={-2}
                      textAnchor="middle"
                      fill={strokeColor}
                      fontSize="9.5"
                      fontWeight="700"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {protoLabel}
                    </text>
                    <text
                      x={0}
                      y={8.5}
                      textAnchor="middle"
                      fill="#cbd5e1"
                      fontSize="8.5"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {subLabel}
                    </text>
                  </g>
                )}
              </g>
            );
          })}

          {/* Nodes Layer */}
          {positionedNodes.map(({ node, x, y, radius, isIsolated }) => {
            const ringColor = getNodeRingColor(node, isIsolated);
            const isSelected = node.id === selectedNodeId;
            const isHovered = hoveredNode?.id === node.id;
            const isSearchMatch = normalizedQuery.length > 0 && searchMatchedNodeIds.has(node.id);
            const isHighlighted = !activeHighlightNodes || activeHighlightNodes.has(node.id);
            const isInferredNode =
              node.kind === 'inferred_gateway' || node.roles.some((r) => r.inferred);

            const showLabel =
              showAllLabels ||
              isSelected ||
              isHovered ||
              isSearchMatch ||
              node.finding_ids.length > 0;

            const rawClass =
              node.classification ||
              (node.kind === 'inferred_gateway'
                ? 'Inferred Gateway'
                : node.scope === 'local'
                ? 'Private Host'
                : node.scope === 'remote'
                ? 'Remote Host'
                : 'Endpoint');
            const classificationText = isIsolated && edges.length > 0
              ? `(${rawClass} • Isolated)`
              : `(${rawClass})`;

            return (
              <g
                key={node.id}
                transform={`translate(${x}, ${y})`}
                opacity={isHighlighted ? 1 : 0.25}
                className="cursor-pointer transition-opacity duration-150"
                onMouseDown={(e) => {
                  if (e.button !== 0) return;
                  e.stopPropagation();
                  dragMovedRef.current = false;
                  setDraggingNodeId(node.id);
                }}
                onMouseEnter={() => setHoveredNode(node)}
                onMouseLeave={() => setHoveredNode(null)}
                onClick={(e) => {
                  e.stopPropagation();
                  if (!dragMovedRef.current) {
                    onSelectEdge(null);
                    onSelectNode(node);
                  }
                }}
              >
                {/* Dashed outer ring for isolated endpoints (matching Reference Image) */}
                {isIsolated && (
                  <circle
                    r={radius + 5}
                    fill="none"
                    stroke="#64748b"
                    strokeOpacity={0.75}
                    strokeWidth={1.5}
                    strokeDasharray="3 3"
                  />
                )}

                {/* Soft outer halo for selected / search-matched / finding nodes */}
                {(isSelected || isHovered || isSearchMatch || node.finding_ids.length > 0) && (
                  <circle
                    r={radius + 6}
                    fill="none"
                    stroke={isSelected || isSearchMatch ? '#22d3ee' : ringColor}
                    strokeOpacity={isSelected || isSearchMatch ? 0.7 : 0.32}
                    strokeWidth={isSelected || isSearchMatch ? 2.5 : 2}
                    strokeDasharray={node.kind === 'inferred_gateway' ? '4 3' : undefined}
                  />
                )}

                {/* Main node circle */}
                <circle
                  r={radius}
                  fill="#0b1329"
                  stroke={isSelected ? '#22d3ee' : ringColor}
                  strokeWidth={isSelected ? 3 : 2.4}
                  strokeDasharray={node.kind === 'inferred_gateway' ? '5 3' : undefined}
                />

                {/* Inner subtle ring */}
                <circle r={Math.max(14, radius - 4)} fill={ringColor} fillOpacity={0.14} />

                {/* Device / Role Vector Icon */}
                {renderNodeIcon(node, isIsolated)}

                {/* Finding Count Badge on top-right of node circle */}
                {node.finding_ids.length > 0 && (
                  <g transform={`translate(${radius * 0.72}, ${-radius * 0.72})`}>
                    <circle
                      r={8.5}
                      fill={
                        node.max_severity === 'Critical' || node.max_severity === 'High'
                          ? '#e11d48'
                          : '#d97706'
                      }
                      stroke="#040917"
                      strokeWidth={1.5}
                    />
                    <text
                      x={0}
                      y={3}
                      textAnchor="middle"
                      fill="#ffffff"
                      fontSize="8.5"
                      fontWeight="700"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {node.finding_ids.length}
                    </text>
                  </g>
                )}

                {/* Non-overlapping 2-line IP + (Classification) label beneath node */}
                {showLabel && (
                  <g transform={`translate(0, ${radius + 15})`}>
                    <rect
                      x={-68}
                      y={-10}
                      width={136}
                      height={30}
                      rx={6}
                      fill="#040917"
                      fillOpacity={0.9}
                      stroke={isSelected ? '#22d3ee' : isInferredNode ? '#f59e0b' : '#1e293b'}
                      strokeWidth={0.8}
                      strokeDasharray={isInferredNode ? '3 2' : undefined}
                    />
                    <text
                      x={0}
                      y={2}
                      textAnchor="middle"
                      fill={isSelected ? '#22d3ee' : '#f8fafc'}
                      fontSize="10.5"
                      fontWeight="700"
                      fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    >
                      {node.id}
                    </text>
                    <text
                      x={0}
                      y={14}
                      textAnchor="middle"
                      fill="#94a3b8"
                      fontSize="9"
                      fontFamily="ui-sans-serif, system-ui, sans-serif"
                    >
                      {classificationText}
                    </text>
                  </g>
                )}
              </g>
            );
          })}
        </g>
      </svg>

      {/* Hover Tooltip Overlay */}
      {(hoveredNode || hoveredEdge) && (
        <div className="absolute top-3 left-3 max-w-xs p-2.5 bg-slate-950/95 border border-slate-700/90 rounded-lg shadow-xl pointer-events-none text-[11px] font-mono text-slate-200 space-y-1 z-10">
          {hoveredNode ? (
            <>
              <div className="flex items-center justify-between gap-3">
                <span className="font-bold text-cyan-300">{hoveredNode.id}</span>
                <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-slate-300 uppercase">
                  {hoveredNode.scope}
                </span>
              </div>
              <div className="text-slate-400 text-[10px]">{hoveredNode.classification}</div>
              <div className="text-slate-300">
                {hoveredNode.packets.toLocaleString()} pkts • {formatBytesShort(hoveredNode.bytes)}
              </div>
              {hoveredNode.roles.map((r, i) => (
                <div key={i} className="text-[10px] text-amber-300/90">
                  [{r.role}
                  {r.inferred ? ' • inferred' : ''}]: {r.basis}
                </div>
              ))}
              {hoveredNode.hop_estimate && (
                <div className="text-[10px] text-slate-400">
                  Hops: ~{hoveredNode.hop_estimate.hops} ({hoveredNode.hop_estimate.basis})
                </div>
              )}
            </>
          ) : hoveredEdge ? (
            <>
              <div className="font-bold text-cyan-300">
                {hoveredEdge.initiator || hoveredEdge.source} &rarr;{' '}
                {hoveredEdge.responder || hoveredEdge.target}
              </div>
              <div className="text-slate-300">
                {hoveredEdge.protocols.join(', ') || 'L2'} • {hoveredEdge.flow_count} flows •{' '}
                {hoveredEdge.packets.toLocaleString()} pkts ({formatBytesShort(hoveredEdge.bytes)})
              </div>
              {(hoveredEdge.kind === 'inferred_l2' || hoveredEdge.inferred) &&
                hoveredEdge.basis && (
                  <div className="text-[10px] text-amber-300">Inferred: {hoveredEdge.basis}</div>
                )}
            </>
          ) : null}
        </div>
      )}

      {/* Zoom, Fit & Center Controls Overlay (Top-Right, matching Reference Image) */}
      <div className="absolute top-3 right-3 flex items-center gap-1 bg-slate-950/90 border border-slate-800 rounded-lg p-1 z-10">
        <button
          type="button"
          title="Zoom in"
          aria-label="Zoom in"
          onClick={() =>
            setTransform((prev) => ({
              ...prev,
              k: Math.min(2.75, prev.k * 1.2),
            }))
          }
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <ZoomIn className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          title="Zoom out"
          aria-label="Zoom out"
          onClick={() =>
            setTransform((prev) => ({
              ...prev,
              k: Math.max(0.35, prev.k / 1.2),
            }))
          }
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <ZoomOut className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          title="Fit to view"
          aria-label="Fit to view"
          onClick={fitToView}
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <Maximize2 className="w-3.5 h-3.5" />
        </button>
        <button
          type="button"
          title="Center on selected endpoint"
          aria-label="Center on selected endpoint"
          onClick={centerOnSelectedNode}
          className="p-1.5 text-slate-400 hover:text-slate-100 hover:bg-slate-800 rounded transition-colors"
        >
          <Crosshair className="w-3.5 h-3.5" />
        </button>
      </div>

      {/* Bottom-Right Watermark Summary */}
      <div className="absolute bottom-2.5 right-3.5 pointer-events-none text-[11px] font-mono text-slate-400/90 bg-slate-950/80 px-2.5 py-1 rounded border border-slate-800/80">
        {nodes.length} endpoints • {totalObservedFlows} observed flows
        {captureFilename ? ` • capture: ${captureFilename}` : ''}
      </div>
    </div>
  );
};

export default TopologyGraph;
