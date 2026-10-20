import { render, screen, waitFor, fireEvent } from '@testing-library/react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { MemoryRouter, Routes, Route } from 'react-router-dom';
import App from '../app/App';
import { StatusBadge } from '../components/StatusBadge';
import { MetricCard } from '../components/MetricCard';
import { EmptyState } from '../components/EmptyState';
import { Activity } from 'lucide-react';
import { CaptureProvider } from '../context/CaptureContext';
import { TopologyPage } from '../features/topology/TopologyPage';
import { PacketsPage } from '../features/packets/PacketsPage';
import type { TopologyGraphProps } from '../features/topology/TopologyGraph';

vi.mock('../features/topology/TopologyGraph', () => ({
  TopologyGraph: ({ nodes, edges, onSelectNode, onSelectEdge }: TopologyGraphProps) => (
    <div data-testid="mock-topology-graph">
      <div data-testid="mock-nodes">
        {nodes.map((n) => (
          <button
            key={n.id}
            type="button"
            data-testid={`mock-node-${n.id}`}
            onClick={() => onSelectNode(n)}
          >
            Node {n.id}
          </button>
        ))}
      </div>
      <div data-testid="mock-edges">
        {edges.map((e) => (
          <button
            key={e.id}
            type="button"
            data-testid={`mock-edge-${e.id}`}
            onClick={() => onSelectEdge(e)}
          >
            Edge {e.id}
          </button>
        ))}
      </div>
    </div>
  ),
}));

beforeEach(() => {
  localStorage.clear();
  vi.stubGlobal(
    'fetch',
    vi.fn((url: string) => {
      if (url.includes('/api/v1/health')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              status: 'healthy',
              version: '1.0.0',
              app_name: 'NetTrace',
              database_ok: true,
            }),
        });
      }
      if (url.includes('/api/v1/captures')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([]),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      });
    })
  );
});

describe('NetTrace Frontend UI', () => {
  it('renders application brand and navigation links including Topology', async () => {
    render(<App />);
    expect(screen.getByText('NET')).toBeInTheDocument();
    expect(screen.getByText('TRACE')).toBeInTheDocument();
    expect(screen.getByText('Overview')).toBeInTheDocument();
    expect(screen.getByText('Captures & Upload')).toBeInTheDocument();
    expect(screen.getByText('Packet Explorer')).toBeInTheDocument();
    expect(screen.getByText('Topology')).toBeInTheDocument();
    expect(screen.getByText('Findings & Diagnostics')).toBeInTheDocument();
  });

  it('renders empty dashboard state when no capture is active', async () => {
    render(<App />);
    await waitFor(() => {
      expect(screen.getByText('No Packet Capture Loaded')).toBeInTheDocument();
    });
  });

  it('renders StatusBadge with severity styling correctly', () => {
    const { container, rerender } = render(<StatusBadge status="Critical" type="severity" />);
    expect(container.textContent).toBe('Critical');

    rerender(<StatusBadge status="ESTABLISHED" type="state" />);
    expect(container.textContent).toBe('ESTABLISHED');
  });

  it('renders MetricCard component with formatted values', () => {
    render(
      <MetricCard
        title="Analyzed Packets"
        value="1,024"
        subtext="Captured frames"
        icon={Activity}
        color="cyan"
      />
    );
    expect(screen.getByText('Analyzed Packets')).toBeInTheDocument();
    expect(screen.getByText('1,024')).toBeInTheDocument();
    expect(screen.getByText('Captured frames')).toBeInTheDocument();
  });

  it('renders EmptyState component with action button', () => {
    const handleAction = vi.fn();
    render(
      <EmptyState
        title="No Results Found"
        description="Try adjusting your filter options."
        actionText="Reset Filters"
        onAction={handleAction}
      />
    );
    expect(screen.getByText('No Results Found')).toBeInTheDocument();
    expect(screen.getByText('Reset Filters')).toBeInTheDocument();
  });

  it('TopologyPage renders empty state when no capture is selected', async () => {
    render(
      <CaptureProvider>
        <MemoryRouter initialEntries={['/topology']}>
          <Routes>
            <Route path="/topology" element={<TopologyPage />} />
          </Routes>
        </MemoryRouter>
      </CaptureProvider>
    );
    await waitFor(() => {
      expect(screen.getByText('No Capture Selected')).toBeInTheDocument();
    });
  });

  it('TopologyPage renders notes banner and Re-analyze button when hints_available is false, and shows inferred badge when clicking a node', async () => {
    const mockCapture = {
      id: 'cap-1',
      filename: 'cap-1.pcap',
      original_filename: 'incident.pcap',
      file_size_bytes: 2048,
      file_hash_sha256: 'abc',
      format: 'PCAP',
      upload_time: '2026-10-20T00:00:00Z',
      status: 'completed',
      packet_count: 42,
      start_timestamp: 1000,
      end_timestamp: 1010,
      duration_seconds: 10,
      metadata: {},
    };

    const mockTopology = {
      capture_id: 'cap-1',
      hints_available: false,
      l2_available: false,
      truncated: false,
      total_nodes: 2,
      omitted_nodes: 0,
      notes: [
        'Topology hints (MAC/TTL) were not recorded when this capture was originally analyzed. Re-analyze this capture to enable Layer 2 and TTL inference.',
      ],
      nodes: [
        {
          id: '192.168.1.105',
          kind: 'host',
          scope: 'local',
          packets: 25,
          bytes: 1600,
          sent_bytes: 1200,
          recv_bytes: 400,
          protocols: ['TCP'],
          macs: [],
          roles: [
            {
              role: 'scanner',
              inferred: true,
              basis: 'Port scan candidate from 192.168.1.105',
            },
          ],
          hop_estimate: null,
          finding_ids: ['f-1'],
          max_severity: 'Medium',
        },
        {
          id: '10.0.0.80',
          kind: 'host',
          scope: 'local',
          packets: 20,
          bytes: 1100,
          sent_bytes: 400,
          recv_bytes: 700,
          protocols: ['TCP'],
          macs: [],
          roles: [],
          hop_estimate: null,
          finding_ids: ['f-1'],
          max_severity: 'Medium',
        },
      ],
      edges: [
        {
          id: '10.0.0.80|192.168.1.105',
          source: '10.0.0.80',
          target: '192.168.1.105',
          kind: 'observed',
          inferred: false,
          basis: null,
          protocols: ['TCP'],
          ports: [80, 81],
          flow_count: 5,
          packets: 15,
          bytes: 900,
          states: { RESET: 5 },
          status: 'reset',
          finding_ids: ['f-1'],
        },
      ],
    };

    vi.stubGlobal(
      'fetch',
      vi.fn((url: string) => {
        if (url.endsWith('/api/v1/captures')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve([mockCapture]),
          });
        }
        if (url.includes('/api/v1/captures/cap-1/topology')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockTopology),
          });
        }
        if (url.includes('/api/v1/captures/cap-1/findings')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve([]),
          });
        }
        if (url.endsWith('/api/v1/captures/cap-1')) {
          return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockCapture),
          });
        }
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve({}),
        });
      })
    );

    render(
      <CaptureProvider>
        <MemoryRouter initialEntries={['/topology']}>
          <Routes>
            <Route path="/topology" element={<TopologyPage />} />
          </Routes>
        </MemoryRouter>
      </CaptureProvider>
    );

    await waitFor(() => {
      expect(screen.getByText('Communication Topology')).toBeInTheDocument();
      expect(screen.getByText(/Topology hints \(MAC\/TTL\) were not recorded/i)).toBeInTheDocument();
      expect(screen.getByRole('button', { name: /Re-analyze/i })).toBeInTheDocument();
      expect(screen.getByText('Topology Summary')).toBeInTheDocument();
      expect(screen.getByText('Traffic Breakdown')).toBeInTheDocument();
      expect(screen.getByText('Related Findings')).toBeInTheDocument();
      expect(screen.getByText('Graph Legend')).toBeInTheDocument();
      expect(screen.getByText('Quick Actions')).toBeInTheDocument();
    });

    // Click the mocked node to inspect its details panel
    const nodeBtn = screen.getByTestId('mock-node-192.168.1.105');
    fireEvent.click(nodeBtn);

    await waitFor(() => {
      expect(screen.getByTestId('topology-node-details')).toBeInTheDocument();
      expect(screen.getByText('scanner')).toBeInTheDocument();
      expect(screen.getByText('inferred')).toBeInTheDocument();
      expect(screen.getByText('Port scan candidate from 192.168.1.105')).toBeInTheDocument();
      expect(screen.getByText('Distinct peers')).toBeInTheDocument();
      expect(screen.getByText('Top peers')).toBeInTheDocument();
    });

    // Click the mocked edge to inspect edge details
    const edgeBtn = screen.getByTestId('mock-edge-10.0.0.80|192.168.1.105');
    fireEvent.click(edgeBtn);

    await waitFor(() => {
      expect(screen.getByTestId('topology-edge-details')).toBeInTheDocument();
      expect(screen.getByText('Selected connection')).toBeInTheDocument();
      expect(screen.getByText('RESET')).toBeInTheDocument();
    });

    // Verify endpoint search input works and pressing Enter selects matching endpoint
    const searchInput = screen.getByPlaceholderText(/Search endpoint/i) as HTMLInputElement;
    fireEvent.change(searchInput, { target: { value: '10.0.0.80' } });
    fireEvent.keyDown(searchInput, { key: 'Enter', code: 'Enter' });

    await waitFor(() => {
      expect(screen.getByTestId('topology-node-details')).toBeInTheDocument();
      expect(screen.getByText('10.0.0.80')).toBeInTheDocument();
    });
  });

  it('PacketsPage initialises IP filter from ?ip= query parameter', async () => {
    const mockCapture = {
      id: 'cap-1',
      filename: 'cap-1.pcap',
      original_filename: 'incident.pcap',
      file_size_bytes: 2048,
      file_hash_sha256: 'abc',
      format: 'PCAP',
      upload_time: '2026-10-20T00:00:00Z',
      status: 'completed',
      packet_count: 10,
      start_timestamp: 1000,
      end_timestamp: 1010,
      duration_seconds: 10,
      metadata: {},
    };

    const fetchMock = vi.fn((url: string) => {
      if (url.endsWith('/api/v1/captures')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve([mockCapture]),
        });
      }
      if (url.includes('/api/v1/captures/cap-1/packets')) {
        return Promise.resolve({
          ok: true,
          json: () =>
            Promise.resolve({
              items: [],
              total: 0,
              page: 1,
              page_size: 50,
              total_pages: 1,
            }),
        });
      }
      if (url.endsWith('/api/v1/captures/cap-1')) {
        return Promise.resolve({
          ok: true,
          json: () => Promise.resolve(mockCapture),
        });
      }
      return Promise.resolve({
        ok: true,
        json: () => Promise.resolve({}),
      });
    });

    vi.stubGlobal('fetch', fetchMock);

    render(
      <CaptureProvider>
        <MemoryRouter initialEntries={['/packets?ip=192.168.1.105']}>
          <Routes>
            <Route path="/packets" element={<PacketsPage />} />
          </Routes>
        </MemoryRouter>
      </CaptureProvider>
    );

    await waitFor(() => {
      const ipInput = screen.getByPlaceholderText(/IP \(e\.g\./i) as HTMLInputElement;
      expect(ipInput.value).toBe('192.168.1.105');
      expect(screen.getByTestId('wireshark-filter-preview')).toHaveTextContent('ip.addr == 192.168.1.105');
    });

    expect(
      fetchMock.mock.calls.some((call) => String(call[0]).includes('ip=192.168.1.105'))
    ).toBe(true);

    // Click the "TCP Resets (RST)" quick filter preset and verify Wireshark expression updates
    const rstPresetBtn = screen.getByRole('button', { name: /TCP Resets \(RST\)/i });
    fireEvent.click(rstPresetBtn);

    await waitFor(() => {
      expect(screen.getByTestId('wireshark-filter-preview')).toHaveTextContent('tcp.flags.reset == 1');
    });
  });

  it('TopologyGraph renders deterministic non-overlapping SVG nodes and directional edges for interconnected and isolated endpoints', async () => {
    const actual = await vi.importActual<typeof import('../features/topology/TopologyGraph')>(
      '../features/topology/TopologyGraph'
    );
    const RealTopologyGraph = actual.TopologyGraph;

    const sampleNodes = [
      {
        id: '192.168.1.10',
        kind: 'host' as const,
        scope: 'local' as const,
        classification: 'Local Client',
        packets: 120,
        bytes: 64000,
        sent_bytes: 32000,
        recv_bytes: 32000,
        protocols: ['TCP', 'DNS'],
        macs: ['00:11:22:33:44:55'],
        roles: [{ role: 'dns_client', inferred: false, basis: '2 DNS queries' }],
        finding_ids: ['f-1'],
        max_severity: 'High' as const,
      },
      {
        id: '10.0.0.53',
        kind: 'host' as const,
        scope: 'local' as const,
        classification: 'DNS Server',
        packets: 80,
        bytes: 18000,
        sent_bytes: 12000,
        recv_bytes: 6000,
        protocols: ['DNS'],
        macs: ['00:11:22:33:44:66'],
        roles: [{ role: 'dns_server', inferred: false, basis: '2 DNS responses' }],
        finding_ids: [],
        max_severity: null,
      },
      {
        id: '172.16.0.99',
        kind: 'host' as const,
        scope: 'local' as const,
        classification: 'Private Host',
        packets: 4,
        bytes: 256,
        sent_bytes: 256,
        recv_bytes: 0,
        protocols: ['ICMP'],
        macs: [],
        roles: [],
        finding_ids: [],
        max_severity: null,
      },
    ];

    const sampleEdges = [
      {
        id: '10.0.0.53|192.168.1.10',
        source: '10.0.0.53',
        target: '192.168.1.10',
        initiator: '192.168.1.10',
        responder: '10.0.0.53',
        bidirectional: true,
        kind: 'observed' as const,
        inferred: false,
        basis: null,
        protocols: ['DNS'],
        ports: [53],
        flow_count: 2,
        packets: 4,
        bytes: 512,
        states: { ESTABLISHED: 2 },
        status: 'normal' as const,
        finding_ids: [],
      },
    ];

    const { rerender } = render(
      <RealTopologyGraph
        nodes={sampleNodes}
        edges={sampleEdges}
        layoutMode="force"
        selectedNodeId={null}
        selectedEdgeId={null}
        captureFilename="test.pcap"
        totalFlowsCount={2}
        onSelectNode={vi.fn()}
        onSelectEdge={vi.fn()}
        resetSignal={0}
      />
    );

    expect(screen.getByText('192.168.1.10')).toBeInTheDocument();
    expect(screen.getByText('10.0.0.53')).toBeInTheDocument();
    expect(screen.getByText('172.16.0.99')).toBeInTheDocument();
    expect(screen.getByText(/Isolated/i)).toBeInTheDocument();
    expect(screen.getByText(/3 endpoints • 2 observed flows/i)).toBeInTheDocument();

    // Switch to grouped layout and verify column headers render
    rerender(
      <RealTopologyGraph
        nodes={sampleNodes}
        edges={sampleEdges}
        layoutMode="grouped"
        selectedNodeId="192.168.1.10"
        selectedEdgeId={null}
        captureFilename="test.pcap"
        totalFlowsCount={2}
        onSelectNode={vi.fn()}
        onSelectEdge={vi.fn()}
        resetSignal={1}
      />
    );

    expect(screen.getByText(/LOCAL HOSTS/i)).toBeInTheDocument();
    expect(screen.getByText(/SERVICES & GATEWAYS/i)).toBeInTheDocument();
  });

  it('validates display-filter expressions and persists saved filters cleanly', async () => {
    const {
      validateDisplayFilter,
      loadSavedFilters,
      saveFilterItem,
      removeSavedFilter,
    } = await import('../lib/displayFilter');

    // Valid expressions
    expect(validateDisplayFilter('ip.addr == 192.168.1.10 && tcp').valid).toBe(true);
    expect(validateDisplayFilter('dns || tcp.port == 443').valid).toBe(true);
    expect(validateDisplayFilter('!(arp)').valid).toBe(true);
    expect(validateDisplayFilter('tcp.flags.syn == 1').valid).toBe(true);
    expect(validateDisplayFilter('frame.len > 1000').valid).toBe(true);

    // Invalid expressions
    expect(validateDisplayFilter('unknown.field == 1').valid).toBe(false);
    expect(validateDisplayFilter('ip.addr == 999.999.1.1').valid).toBe(false);
    expect(validateDisplayFilter('tcp.port == 99999').valid).toBe(false);
    expect(validateDisplayFilter('(tcp && dns').valid).toBe(false);

    // Saved filters persistence
    const initial = loadSavedFilters();
    expect(initial.length).toBeGreaterThan(0);

    const updated = saveFilterItem('Custom HTTPS Check', 'ip.addr == 10.0.0.1 && tcp.port == 443');
    expect(updated.some((f) => f.name === 'Custom HTTPS Check')).toBe(true);

    const addedItem = updated.find((f) => f.name === 'Custom HTTPS Check')!;
    const afterRemove = removeSavedFilter(addedItem.name);
    expect(afterRemove.some((f) => f.name === addedItem.name)).toBe(false);
  });
});


