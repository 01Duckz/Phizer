import { useState } from 'react';
import './index.css';

const EDUCATIONAL_CONTENT = {
  spf: { title: 'What is SPF?', body: 'Sender Policy Framework (SPF) acts like a guest list. It explicitly states which IP addresses or servers are allowed to send emails on behalf of that domain.' },
  dkim: { title: 'What is DKIM?', body: 'DomainKeys Identified Mail (DKIM) adds a digital cryptographic signature to emails. It proves that the email was genuinely sent by the domain owner and wasn’t tampered with in transit.' },
  dmarc: { title: 'What is DMARC?', body: 'DMARC ties SPF and DKIM together. It verifies that the domain in the "From" address actually matches the domains validated by SPF and DKIM, ensuring the sender’s identity isn’t spoofed.' },
  relay: { title: 'What are Email Relays?', body: 'When you send an email, it rarely goes directly to the recipient. It "hops" from one mail server (relay) to another across the internet. Attackers often route emails through suspicious relays to hide their origin.' },
  headers: { title: 'What are Email Headers?', body: 'Headers are hidden digital footprints attached to every email. They contain routing data, authentication results, and software details used by the sender.' }
};

function App() {
  const [viewState, setViewState] = useState('upload'); 
  const [report, setReport] = useState(null);
  const [error, setError] = useState(null);
  const [modalState, setModalState] = useState({ isOpen: false, title: '', body: null });

  const handleFileUpload = async (event) => {
    event.preventDefault();
    const file = event.target.fileInput.files[0];
    if (!file) return;

    setViewState('scanning');
    setError(null);

    const formData = new FormData();
    formData.append('file', file);

    try {
      const response = await fetch('/api/index', { method: 'POST', body: formData });
      if (!response.ok) throw new Error('Failed to scan file');
      const data = await response.json();
      setReport(data);
      setViewState('ready'); 
    } catch (err) {
      setError(err.message);
      setViewState('upload'); 
    }
  };

  const openEduModal = (key) => {
    setModalState({ isOpen: true, title: EDUCATIONAL_CONTENT[key].title, body: <p>{EDUCATIONAL_CONTENT[key].body}</p> });
  };

  const openVtModal = (domain, details) => {
    setModalState({
      isOpen: true,
      title: `Malware Analysis: ${domain}`,
      body: (
        <ul className="handwriting-list m-0 ps-3">
          {details.map((d, i) => (
            <li key={i} className="mb-2"><strong>{d.vendor}:</strong> Flagged as {d.result}</li>
          ))}
        </ul>
      )
    });
  };

  const auth = report?.security_checks?.authentication || {};
  const evidenceList = report?.security_checks?.evidence || [];
  const urlList = report?.urls || [];
  const headersList = report?.headers || [];
  const relaysList = report?.relays || [];
  const isSpoofed = report?.security_checks?.spoofing_flagged;

  // Generate plain-english explanations based on the report
  const getAnalysisExplanations = () => {
    const explanations = [];
    if (isSpoofed) {
      explanations.push({ title: "❌ Authentication Failed", desc: "The sender's identity could not be verified by the domain owner. This is highly indicative of a phishing attempt." });
      evidenceList.forEach(e => explanations.push({ title: "⚠️ Red Flag", desc: e }));
    } else {
      explanations.push({ title: "✅ Identity Verified", desc: "The email origin matches the official records of the domain." });
      if (auth.spf === 'PASS') explanations.push({ title: "✅ Approved Server (SPF)", desc: "The email was sent from an IP address officially authorized by the domain." });
      if (auth.dkim === 'PASS') explanations.push({ title: "✅ Intact Signature (DKIM)", desc: "The email has a valid digital signature and wasn't altered in transit." });
      if (auth.dmarc === 'PASS') explanations.push({ title: "✅ Domain Alignment (DMARC)", desc: "The 'From' address exactly matches the verified server details." });
    }
    
    if (explanations.length === 1 && !isSpoofed) {
      explanations.push({ title: "⚠️ Caution (Missing Records)", desc: "This email lacks strong authentication records (SPF/DKIM/DMARC). While not explicitly flagged as a spoof, handle with care." });
    }
    return explanations;
  };

  return (
    <div className={`app-wrapper ${viewState !== 'results' ? 'home-bg' : 'results-bg'}`}>
      <div className="container py-5" style={{ maxWidth: '1000px' }}>
        
        {/* VIEW 1: UPLOAD SCREEN */}
        {viewState !== 'results' && (
          <div className="d-flex flex-column align-items-center mt-4">
            <div className="bento-card main-scanner-card p-4 text-center w-100 mb-4">
              <div className="bento-pill dark-pill mx-auto mb-3" style={{ width: 'fit-content' }}>PHIZER OS v2.0</div>
              <h1 className="bento-header mb-4">Email Scanner</h1>
              
              {viewState === 'upload' && (
                <form onSubmit={handleFileUpload}>
                  <div className="mb-4">
                    <input type="file" name="fileInput" className="bento-input form-control" accept=".eml" required />
                  </div>
                  <button type="submit" className="bento-btn w-100 justify-content-center">
                    <span className="btn-icon">▷</span> ANALYZE .EML
                  </button>
                </form>
              )}

              {viewState === 'scanning' && (
                <div className="py-4">
                  <div className="digital-text mb-2">SCANNING...</div>
                  <div className="bento-progress-bar"><div className="bento-progress-fill"></div></div>
                </div>
              )}

              {viewState === 'ready' && (
                <div className="py-3">
                  <div className="bento-pill dark-pill mx-auto mb-4" style={{ fontSize: '1.2rem', width: 'fit-content' }}>✓ COMPLETE</div>
                  <button onClick={() => setViewState('results')} className="bento-btn w-100 justify-content-center">
                    VIEW REPORT <span className="btn-icon">▷</span>
                  </button>
                </div>
              )}
              {error && <div className="bento-card dark-card mt-3 p-2">{error}</div>}
            </div>

            <div className="bento-card info-rectangle p-4 text-start w-100" style={{ maxWidth: '600px' }}>
              <h3 className="handwriting-text fs-4 mb-2">What is this website?</h3>
              <p className="mb-3">Phizer is an educational forensic tool designed to help you analyze raw email files (.eml). It breaks down hidden routing data to verify if an email truly came from who it claims to be from, or if it contains hidden malicious links.</p>
              <h3 className="handwriting-text fs-4 mb-2">What is Phishing?</h3>
              <p className="mb-0">Phishing is a cyberattack where scammers disguise themselves as trusted entities (like your bank or a coworker) to trick you into clicking malicious links, downloading malware, or revealing sensitive passwords.</p>
            </div>
          </div>
        )}

        {/* VIEW 2: RESULTS DASHBOARD */}
        {viewState === 'results' && report && (
          <div className="results-dashboard">
            <div className="d-flex justify-content-between align-items-center mb-4 gap-3">
              <button onClick={() => setViewState('upload')} className="bento-btn bento-btn-sm">← Back</button>
              <div className="bento-card digital-clock-widget px-4 py-2 m-0 text-center flex-grow-1">
                <span className="digital-text large-digital">ANALYSIS REPORT</span>
              </div>
            </div>

            <div className="row g-4">
              
              {/* SECTION 1: SECURITY STATUS & AUTHENTICATION */}
              <div className="col-md-5">
                <div className="bento-card dark-card h-100 p-4 text-center d-flex flex-column justify-content-center">
                  <div className="handwriting-text mb-2">Security Status</div>
                  {isSpoofed ? (
                    <>
                      <div className="digital-text large-digital text-danger mb-2">FAILED</div>
                      <div className="bento-pill light-pill mx-auto">Spoofing Detected</div>
                    </>
                  ) : (
                    <>
                      <div className="digital-text large-digital mb-2">PASSED</div>
                      <div className="bento-pill light-pill mx-auto">Sender Verified</div>
                    </>
                  )}
                </div>
              </div>

              <div className="col-md-7">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3">Authentication Records</span>
                  <div className="d-flex flex-column gap-3 mb-3">
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>SPF</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${auth.spf === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>{auth.spf}</span>
                      <button className="help-icon" onClick={() => openEduModal('spf')}>?</button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DKIM</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${auth.dkim === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>{auth.dkim}</span>
                      <button className="help-icon" onClick={() => openEduModal('dkim')}>?</button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DMARC</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${auth.dmarc === 'PASS' ? 'dark-pill' : 'outline-pill'}`}>{auth.dmarc}</span>
                      <button className="help-icon" onClick={() => openEduModal('dmarc')}>?</button>
                    </div>
                  </div>
                  <details className="bento-accordion">
                    <summary>View Analyzation Basis</summary>
                    <div className="accordion-content horizontal-scroll pixel-mono">{auth.raw_basis}</div>
                  </details>
                </div>
              </div>

              {/* SECTION 2: EMAIL RELAYS (Graph + Table) */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4">Email Relay Hops</span>
                    <button className="help-icon" onClick={() => openEduModal('relay')}>?</button>
                  </div>
                  
                  {relaysList.length === 0 ? (
                    <div className="text-muted">No relay information found.</div>
                  ) : (
                    <>
                      {/* Visual Graph On Top */}
                      <div className="relay-graph-container mb-4">
                        {relaysList.map((relay, idx) => (
                          <div key={idx} className="relay-bar mb-2" style={{ width: `${Math.min(30 + (idx * 15), 100)}%` }}>
                            <span className="relay-hop-badge">Hop {relay.hop}</span>
                          </div>
                        ))}
                      </div>

                      {/* Detailed Table Below */}
                      <div className="table-responsive">
                        <table className="bento-table">
                          <thead>
                            <tr>
                              <th style={{ width: '80px' }}>Hop</th>
                              <th>Server / Routing Details</th>
                            </tr>
                          </thead>
                          <tbody>
                            {relaysList.map((relay, idx) => (
                              <tr key={idx}>
                                <td><strong>{relay.hop}</strong></td>
                                <td className="pixel-mono text-break">{relay.detail}</td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* SECTION 3: SPLIT DASHBOARDS (Explanation & Links) */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4">Analysis Breakdown</span>
                  <p className="small mb-3">Simple explanations of why this email passed or failed security checks:</p>
                  
                  <div className="d-flex flex-column gap-3">
                    {getAnalysisExplanations().map((exp, idx) => (
                      <div key={idx} className="bento-list-item" style={{ background: '#E2E4E9' }}>
                        <strong className="d-block mb-1">{exp.title}</strong>
                        <span style={{ fontSize: '0.95rem' }}>{exp.desc}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4">Embedded Links Analysis</span>
                  {urlList.length === 0 ? (
                    <div className="text-muted text-center mt-4">No external links found in the email body.</div>
                  ) : (
                    <div className="d-flex flex-column gap-2">
                      {urlList.map((item, idx) => {
                        const vt = item?.vt_reputation || {};
                        const isMalicious = vt.malicious > 0;
                        return (
                          <div key={idx} className="bento-list-item horizontal-scroll d-flex justify-content-between align-items-center gap-3">
                            <span className="text-nowrap">{item?.domain || 'N/A'}</span>
                            
                            {vt.status === 'scored' ? (
                              isMalicious ? (
                                <button 
                                  onClick={() => openVtModal(item.domain, vt.details)} 
                                  className="bento-pill dark-pill text-nowrap pointer-hover" 
                                  style={{ border: 'none', background: '#dc3545' }}
                                >
                                  {vt.malicious} MALICIOUS (Details)
                                </button>
                              ) : (
                                <span className="bento-pill dark-pill text-nowrap">0 MALICIOUS</span>
                              )
                            ) : (
                              <span className="bento-pill outline-pill text-nowrap">{vt.message || 'UNSCORED'}</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* SECTION 4: RAW HEADERS (1-4 Lines scrollable) */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4">Raw Headers Found</span>
                    <button className="help-icon" onClick={() => openEduModal('headers')}>?</button>
                  </div>
                  
                  <div className="row g-3">
                    {headersList.map((hdr, idx) => (
                      <div key={idx} className="col-md-6 col-lg-4">
                        <div className="bento-list-item h-100">
                          <strong className="d-block mb-1 text-truncate" title={hdr.name}>{hdr.name}</strong>
                          {/* This box is restricted to ~4 lines and handles long text cleanly */}
                          <div className="header-content-box pixel-mono">
                            {hdr.value}
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

            </div>
          </div>
        )}

        {/* MODAL SYSTEM */}
        {modalState.isOpen && (
          <div className="bento-modal-backdrop" onClick={() => setModalState({ ...modalState, isOpen: false })}>
            <div className="bento-card p-4 modal-content-bento" onClick={(e) => e.stopPropagation()}>
              <div className="d-flex justify-content-between align-items-center mb-4">
                <h4 className="handwriting-text m-0 fs-3">{modalState.title}</h4>
                <button onClick={() => setModalState({ ...modalState, isOpen: false })} className="bento-btn bento-btn-icon">X</button>
              </div>
              <div className="modal-body-content" style={{ fontSize: '1.1rem' }}>
                {modalState.body}
              </div>
            </div>
          </div>
        )}

      </div>
    </div>
  );
}

export default App;