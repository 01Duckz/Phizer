import { useState } from 'react';
import './index.css';

const EDUCATIONAL_CONTENT = {
  spf: { title: 'What is SPF?', body: 'Sender Policy Framework (SPF) is a security record in a domain’s DNS. It acts like a guest list, explicitly stating which IP addresses or servers are allowed to send emails on behalf of that domain.' },
  dkim: { title: 'What is DKIM?', body: 'DomainKeys Identified Mail (DKIM) adds a digital cryptographic signature to emails. It proves that the email was genuinely sent by the domain owner and wasn’t tampered with while traveling across the internet.' },
  dmarc: { title: 'What is DMARC?', body: 'DMARC ties SPF and DKIM together. It verifies that the domain in the "From" address actually matches the domains validated by SPF and DKIM, ensuring the sender’s identity isn’t spoofed.' },
  relay: { title: 'What are Email Relays?', body: 'When you send an email, it rarely goes directly to the recipient. It "hops" from one mail server (relay) to another across the internet. Attackers often route emails through suspicious or compromised relays.' },
  headers: { title: 'What are Email Headers?', body: 'Headers are hidden digital footprints attached to every email. They contain routing data, authentication results, and software details used by the sender. Analyzing these helps uncover the email’s true origin.' }
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
      title: `Malicious Indicators: ${domain}`,
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
  const metadata = report?.metadata || {};
  const evidenceList = report?.security_checks?.evidence || [];
  const urlList = report?.urls || [];
  const headersList = report?.headers || [];
  const relaysList = report?.relays || [];
  const isSpoofed = report?.security_checks?.spoofing_flagged;

  return (
    <div className={`app-wrapper ${viewState !== 'results' ? 'home-bg' : 'results-bg'}`}>
      <div className="container py-5" style={{ maxWidth: '950px' }}>
        
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

            {/* EDUCATIONAL HOME RECTANGLE */}
            <div className="bento-card info-rectangle p-4 text-start w-100" style={{ maxWidth: '600px' }}>
              <h3 className="handwriting-text fs-4 mb-2">What is this website?</h3>
              <p className="mb-3">Phizer is a forensic tool designed to help you analyze raw email files (.eml). It breaks down hidden routing data to verify if an email truly came from who it claims to be from, or if it contains hidden malicious links.</p>
              <h3 className="handwriting-text fs-4 mb-2">What is Phishing?</h3>
              <p className="mb-0">Phishing is a cyberattack where scammers disguise themselves as trusted entities (like your bank or a coworker) to trick you into clicking malicious links, downloading malware, or revealing sensitive passwords.</p>
            </div>
          </div>
        )}

        {viewState === 'results' && report && (
          <div className="results-dashboard">
            <div className="d-flex justify-content-between align-items-center mb-4 gap-3">
              <button onClick={() => setViewState('upload')} className="bento-btn bento-btn-sm">← Back</button>
              <div className="bento-card digital-clock-widget px-4 py-2 m-0 text-center flex-grow-1">
                <span className="digital-text large-digital">ANALYSIS REPORT</span>
              </div>
            </div>

            <div className="row g-4">
              
              {/* SECURITY STATUS */}
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

              {/* AUTHENTICATION & DROPDOWN */}
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
                    <div className="accordion-content horizontal-scroll pixel-mono">
                      {auth.raw_basis}
                    </div>
                  </details>
                </div>
              </div>

              {/* RELAY PATH GRAPH */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-3">
                    <span className="handwriting-text m-0">Email Relay Path (Hops)</span>
                    <button className="help-icon" onClick={() => openEduModal('relay')}>?</button>
                  </div>
                  
                  {relaysList.length === 0 ? (
                    <div className="text-muted">No relay information found.</div>
                  ) : (
                    <div className="relay-graph-container">
                      {relaysList.map((relay, idx) => {
                        const barWidth = 30 + (idx * 10); 
                        return (
                          <div key={idx} className="relay-hop">
                            <div className="relay-bar" style={{ width: `${barWidth > 100 ? 100 : barWidth}%` }}>
                              <span className="relay-hop-badge">Hop {relay.hop}</span>
                            </div>
                            <div className="relay-detail horizontal-scroll mt-1">
                              {relay.detail}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* ALL HEADERS LIST */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-3">
                    <span className="handwriting-text m-0">Raw Headers Found</span>
                    <button className="help-icon" onClick={() => openEduModal('headers')}>?</button>
                  </div>
                  <div className="header-list-container">
                    {headersList.map((hdr, idx) => (
                      <div key={idx} className="bento-list-item mb-2 horizontal-scroll d-flex gap-3">
                        <strong className="text-nowrap" style={{ minWidth: '150px' }}>{hdr.name}:</strong>
                        <span className="pixel-mono text-nowrap">{hdr.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* EMBEDDED LINKS */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <span className="handwriting-text d-block mb-3">Embedded Domains (VirusTotal)</span>
                  {urlList.length === 0 ? (
                    <div className="text-muted text-center mt-4">No external links found.</div>
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
                                  {vt.malicious} MALICIOUS (Click for details)
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

            </div>
          </div>
        )}

        {/* REUSABLE EDUCATIONAL MODAL */}
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