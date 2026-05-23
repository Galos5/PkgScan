import React, { useState } from 'react';
import { Shield, ShieldAlert, ShieldCheck, Search, Laptop, Loader2, Info } from 'lucide-react';

function App() {
  const [endpointId, setEndpointId] = useState('');
  const [loading, setLoading] = useState(false);
  const [report, setReport] = useState(null);
  const [error, setError] = useState('');

  const fetchReport = async (e) => {
    e.preventDefault();
    if (!endpointId.trim()) return;

    setLoading(true);
    setError('');
    setReport(null);

    try {
      const response = await fetch(`http://localhost:8000/api/reports/${endpointId.trim()}`);

      if (!response.ok) {
        throw new Error('Server responded with an error');
      }

      const data = await response.json();

      if (data.status && data.status.includes('No scans found')) {
        setError(`No scan history found for endpoint: "${endpointId}"`);
      } else {
        setReport(data);
      }
    } catch (err) {
      setError('Failed to connect to PkgScan server. Make sure the backend is running.');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div style={{ backgroundColor: '#0f172a', color: '#f8fafc', minHeight: '100vh', fontFamily: 'system-ui, sans-serif', padding: '2rem' }}>

      {/* Header */}
      <header style={{ display: 'flex', alignItems: 'center', gap: '1rem', maxWidth: '1200px', margin: '0 auto 3rem auto', borderBottom: '1px solid #334155', paddingBottom: '1rem' }}>
        <Shield size={36} color="#38bdf8" />
        <div>
          <h1 style={{ margin: 0, fontSize: '1.75rem', fontWeight: 'bold' }}>PkgScan Dashboard</h1>
          <p style={{ margin: 0, color: '#94a3b8', fontSize: '0.875rem' }}>Endpoint Vulnerability Monitor</p>
        </div>
      </header>

      <main style={{ maxWidth: '1200px', margin: '0 auto' }}>

        {/* Search Bar */}
        <section style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155', marginBottom: '2rem' }}>
          <form onSubmit={fetchReport} style={{ display: 'flex', gap: '1rem' }}>
            <div style={{ flex: 1, position: 'relative', display: 'flex', alignItems: 'center' }}>
              <Search size={20} color="#64748b" style={{ position: 'absolute', left: '1rem' }} />
              <input
                type="text"
                placeholder="Enter Endpoint ID (e.g., Gal-Laptop-Agent-v2)"
                value={endpointId}
                onChange={(e) => setEndpointId(e.target.value)}
                style={{ width: '100%', backgroundColor: '#0f172a', border: '1px solid #475569', borderRadius: '8px', padding: '0.75rem 1rem 0.75rem 3rem', color: '#fff', fontSize: '1rem', outline: 'none' }}
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              style={{ backgroundColor: '#38bdf8', color: '#0f172a', border: 'none', borderRadius: '8px', padding: '0.75rem 2rem', fontSize: '1rem', fontWeight: 'bold', cursor: 'pointer', display: 'flex', alignItems: 'center', gap: '0.5rem' }}
            >
              {loading ? <Loader2 size={20} style={{ animation: 'spin 1s linear infinite' }} /> : 'Analyze'}
            </button>
          </form>
        </section>

        {/* Error Alert */}
        {error && (
          <div style={{ backgroundColor: '#7f1d1d', border: '1px solid #f87171', color: '#fca5a5', padding: '1rem', borderRadius: '8px', marginBottom: '2rem' }}>
            {error}
          </div>
        )}

        {/* Report Results */}
        {report && (
          <section>
            {/* Summary Cards */}
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(250px, 1fr))', gap: '1.5rem', marginBottom: '2rem' }}>
              <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                <Laptop size={32} color="#94a3b8" />
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Endpoint Host</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 'bold' }}>{report.endpoint_id}</div>
                </div>
              </div>

              <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155', display: 'flex', alignItems: 'center', gap: '1rem' }}>
                {report.total_vulnerabilities > 0 ? <ShieldAlert size={32} color="#ef4444" /> : <ShieldCheck size={32} color="#22c55e" />}
                <div>
                  <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Security Status</div>
                  <div style={{ fontSize: '1.25rem', fontWeight: 'bold', color: report.total_vulnerabilities > 0 ? '#ef4444' : '#22c55e' }}>
                    {report.total_vulnerabilities > 0 ? `${report.total_vulnerabilities} Vulnerabilities` : 'Secured / Safe'}
                  </div>
                </div>
              </div>

              <div style={{ backgroundColor: '#1e293b', padding: '1.5rem', borderRadius: '12px', border: '1px solid #334155', display: 'flex', gap: '1rem', flexDirection: 'column', justifyContent: 'center' }}>
                <div style={{ fontSize: '0.875rem', color: '#94a3b8' }}>Last Scanned Time (UTC)</div>
                <div style={{ fontSize: '1.1rem', fontWeight: 'bold' }}>{report.scanned_at}</div>
              </div>
            </div>

            {/* Vulnerabilities Table */}
            <div style={{ backgroundColor: '#1e293b', borderRadius: '12px', border: '1px solid #334155', overflow: 'hidden' }}>
              <div style={{ padding: '1.25rem 1.5rem', borderBottom: '1px solid #334155', fontWeight: 'bold', fontSize: '1.1rem' }}>
                Detected Security Flaws
              </div>

              {report.vulnerabilities.length === 0 ? (
                <div style={{ padding: '3rem', textAlign: 'center', color: '#94a3b8' }}>
                  <ShieldCheck size={48} color="#22c55e" style={{ margin: '0 auto 1rem auto', display: 'block' }} />
                  No vulnerable open-source packages found on this endpoint.
                </div>
              ) : (
                <table style={{ width: '100%', borderCollapse: 'collapse', textAlign: 'left' }}>
                  <thead>
                    <tr style={{ backgroundColor: '#0f172a', color: '#94a3b8', fontSize: '0.875rem' }}>
                      <th style={{ padding: '1rem 1.5rem' }}>Package Name</th>
                      <th style={{ padding: '1rem 1.5rem' }}>Current Version</th>
                      <th style={{ padding: '1rem 1.5rem' }}>Ecosystem</th>
                      <th style={{ padding: '1rem 1.5rem' }}>Remediation Advice</th>
                      <th style={{ padding: '1rem 1.5rem' }}>Vulnerability Log Details</th>
                    </tr>
                  </thead>
                  <tbody>
                    {report.vulnerabilities.map((pkg, index) => (
                      <tr key={index} style={{ borderBottom: index === report.vulnerabilities.length - 1 ? 'none' : '1px solid #334155' }}>
                        <td style={{ padding: '1rem 1.5rem', fontWeight: '600', color: '#fca5a5' }}>{pkg.name}</td>
                        <td style={{ padding: '1rem 1.5rem', color: '#cbd5e1' }}>v{pkg.version}</td>
                        <td style={{ padding: '1rem 1.5rem' }}>
                          <span style={{ backgroundColor: '#312e81', color: '#c7d2fe', padding: '0.25rem 0.5rem', borderRadius: '4px', fontSize: '0.75rem', fontWeight: 'bold' }}>
                            {pkg.ecosystem.toUpperCase()}
                          </span>
                        </td>
                        <td style={{ padding: '1rem 1.5rem' }}>
                          {pkg.patched_version === 'UNSAFE_FIX_FOUND' ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                              <span style={{ color: '#f97316', fontSize: '0.875rem', fontWeight: 'bold' }}>
                                ⚠️ Fix version is unstable or vulnerable
                              </span>
                              <span style={{ color: '#94a3b8', fontSize: '0.75rem' }}>
                                Review data sources before updating manually.
                              </span>
                            </div>
                          ) : pkg.patched_version ? (
                            <div style={{ display: 'flex', flexDirection: 'column', gap: '0.25rem' }}>
                              <span style={{ color: '#4ade80', fontSize: '0.875rem', fontWeight: 'bold' }}>
                                Fix available in v{pkg.patched_version}
                              </span>
                              <span style={{ color: '#64748b', fontSize: '0.75rem', fontFamily: 'monospace' }}>
                                npm i {pkg.name}@{pkg.patched_version}
                              </span>
                            </div>
                          ) : (
                            <span style={{ color: '#e2e8f0', fontSize: '0.875rem', display: 'flex', alignItems: 'center', gap: '0.25rem' }}>
                              <Info size={14} color="#94a3b8" /> No patch released yet
                            </span>
                          )}
                        </td>
                        <td style={{ padding: '1rem 1.5rem', color: '#94a3b8', fontSize: '0.875rem', maxWidth: '300px', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }} title={pkg.details}>
                          {pkg.details}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </section>
        )}
      </main>

      <style>{`
        @keyframes spin {
          from { transform: rotate(0deg); }
          to { transform: rotate(360deg); }
        }
      `}</style>
    </div>
  );
}

export default App;