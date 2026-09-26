import { useState } from 'react';
import './index.css';

const EDUCATIONAL_CONTENT = {
  spf: { title: 'What is SPF?', body: 'Sender Policy Framework (SPF) acts like a guest list. It explicitly states which IP addresses or servers are allowed to send emails on behalf of that domain.' },
  dkim: { title: 'What is DKIM?', body: 'DomainKeys Identified Mail (DKIM) adds a digital cryptographic signature to emails. It proves that the email was genuinely sent by the domain owner and wasn’t tampered with in transit.' },
  dmarc: { title: 'What is DMARC?', body: 'DMARC ties SPF and DKIM together. It verifies that the domain in the "From" address actually matches the domains validated by SPF and DKIM, ensuring the sender’s identity isn’t spoofed.' },
  relay: { title: 'What are Email Relays?', body: 'When you send an email, it rarely goes directly to the recipient. It "hops" from one mail server (relay) to another across the internet. Attackers often route emails through suspicious relays to hide their origin.' },
  headers: { title: 'What are Email Headers?', body: 'Headers are hidden digital footprints attached to every email. They contain routing data, authentication results, and software details used by the sender.' }
};

const getAuthColor = (status) => {
  if (status === 'PASS') return 'pass-pill';
  if (status === 'FAIL') return 'fail-pill';
  return 'neutral-pill';
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

  // Extract important headers
  const importantKeys = ['Subject', 'From', 'To', 'Date'];
  const importantHeaders = importantKeys.map(key => {
    const found = headersList.find(h => h.name.toLowerCase() === key.toLowerCase());
    return { name: key, value: found ? found.value : 'N/A' };
  });

  // Filter out important headers from the bottom raw headers list
  const remainingHeaders = headersList.filter(
    h => !importantKeys.some(key => key.toLowerCase() === h.name.toLowerCase())
  );

  return (
    <div className={`app-wrapper ${viewState !== 'results' ? 'home-bg' : 'results-bg'}`}>
      <div className="container py-5 d-flex flex-column" style={{ maxWidth: '1000px', minHeight: '100vh' }}>
        
        {/* VIEW 1: UPLOAD SCREEN */}
        {viewState !== 'results' && (
          <div className="d-flex flex-column align-items-center justify-content-center flex-grow-1">
            
            {/* Centered Scanner */}
            <div className="bento-card main-scanner-card p-4 text-center w-100 mb-5" style={{ maxWidth: '600px', marginTop: '-10vh' }}>
              <div className="bento-pill dark-pill mx-auto mb-3" style={{ width: 'fit-content' }}>PHIZER OS v2.0</div>
              <h1 className="bento-header mb-4">Email Scanner</h1>
              
              {viewState === 'upload' && (
                <form onSubmit={handleFileUpload}>
                  <div className="mb-4">
                    <input type="file" name="fileInput" className="bento-input form-control" accept=".eml" required />
                  </div>
                  <button type="submit" className="bento-btn w-100 justify-content-center">
                    <i className="bi bi-play-fill btn-icon"></i> ANALYZE .EML
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
                  <div className="bento-pill dark-pill mx-auto mb-4" style={{ fontSize: '1.2rem', width: 'fit-content' }}>
                    <i className="bi bi-check2"></i> COMPLETE
                  </div>
                  <button onClick={() => setViewState('results')} className="bento-btn w-100 justify-content-center">
                    VIEW REPORT <i className="bi bi-arrow-right-short btn-icon"></i>
                  </button>
                </div>
              )}
              {error && <div className="bento-card dark-card mt-3 p-2 text-danger"><i className="bi bi-exclamation-triangle"></i> {error}</div>}
            </div>

            {/* Pushed down info section */}
            <div className="bento-card info-rectangle p-4 text-start w-100 mt-5" style={{ maxWidth: '800px' }}>
              <h3 className="handwriting-text fs-4 mb-2"><i className="bi bi-info-circle"></i> What is this website?</h3>
              <p className="mb-4">Phizer is an educational forensic tool designed to help you analyze raw email files (.eml). It breaks down hidden routing data to verify if an email truly came from who it claims to be from, or if it contains hidden malicious links.</p>
              <h3 className="handwriting-text fs-4 mb-2"><i className="bi bi-shield-exclamation"></i> What is Phishing?</h3>
              <p className="mb-0">Phishing is a cyberattack where scammers disguise themselves as trusted entities (like your bank or a coworker) to trick you into clicking malicious links, downloading malware, or revealing sensitive passwords.</p>
            </div>
          </div>
        )}

        {/* VIEW 2: RESULTS DASHBOARD */}
        {viewState === 'results' && report && (
          <div className="results-dashboard">
            <div className="d-flex justify-content-between align-items-center mb-4 gap-3">
              <button onClick={() => setViewState('upload')} className="bento-btn bento-btn-sm"><i className="bi bi-arrow-left"></i> Back</button>
              <div className="bento-card digital-clock-widget px-4 py-2 m-0 text-center flex-grow-1">
                <span className="digital-text large-digital">ANALYSIS REPORT</span>
              </div>
            </div>

            <div className="row g-4">
              
              {/* SECTION 1: SECURITY STATUS & AUTHENTICATION */}
              <div className="col-md-5">
                <div className={`bento-card h-100 p-4 text-center d-flex flex-column justify-content-center ${!isSpoofed ? 'safe-card' : 'dark-card'}`}>
                  <div className="handwriting-text mb-2 text-white">Security Status</div>
                  {isSpoofed ? (
                    <>
                      <div className="digital-text large-digital text-danger mb-2">FAILED</div>
                      <div className="bento-pill light-pill mx-auto"><i className="bi bi-shield-x"></i> Spoofing Detected</div>
                    </>
                  ) : (
                    <>
                      <div className="digital-text large-digital text-white mb-2">PASSED</div>
                      <div className="bento-pill light-pill mx-auto"><i className="bi bi-shield-check"></i> Sender Verified</div>
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
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.spf)}`}>{auth.spf || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('spf')}><i className="bi bi-question-lg"></i></button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DKIM</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.dkim)}`}>{auth.dkim || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('dkim')}><i className="bi bi-question-lg"></i></button>
                    </div>
                    <div className="d-flex align-items-center gap-2">
                      <strong style={{ width: '60px' }}>DMARC</strong>
                      <span className={`bento-pill flex-grow-1 text-center ${getAuthColor(auth.dmarc)}`}>{auth.dmarc || 'NONE'}</span>
                      <button className="help-icon" onClick={() => openEduModal('dmarc')}><i className="bi bi-question-lg"></i></button>
                    </div>
                  </div>
                </div>
              </div>

              {/* SECTION 1.5: IMPORTANT HEADERS (Added Scroll-X) */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-envelope-paper"></i> Important Email Details</span>
                  <div className="row g-3">
                    {importantHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6">
                        <div className="bento-list-item h-100">
                          <strong className="d-block mb-1 text-muted small text-uppercase">{hdr.name}</strong>
                          <div className="pixel-mono fs-6 scroll-x">{hdr.value}</div>
                        </div>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* SECTION 2: EMAIL RELAYS (Graph + Enhanced Table) */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4"><i className="bi bi-router"></i> Email Relay Hops</span>
                    <button className="help-icon" onClick={() => openEduModal('relay')}><i className="bi bi-question-lg"></i></button>
                  </div>
                  
                  {relaysList.length === 0 ? (
                    <div className="text-muted">No relay information found.</div>
                  ) : (
                    <>
                      <div className="relay-chart-container mb-4">
                        <div className="chart-grid">
                          <div className="grid-line"></div>
                          <div className="grid-line"></div>
                          <div className="grid-line"></div>
                          <div className="grid-line"></div>
                          <div className="grid-line"></div>
                        </div>
                        
                        {relaysList.map((relay, idx) => {
                          const delayNum = parseFloat(relay.delay) || 0;
                          const maxScale = Math.max(...relaysList.map(r => parseFloat(r.delay) || 0), 1.2);
                          const widthPct = (delayNum / maxScale) * 100;

                          let label = '';
                          if (relay.from && relay.by) label = `From ${relay.from} to ${relay.by}`;
                          else if (relay.from) label = `From ${relay.from}`;
                          else if (relay.by) label = `to ${relay.by}`;
                          else label = `Hop ${relay.hop || idx + 1}`;

                          return (
                            <div key={idx} className="chart-row">
                              <div className="chart-label scroll-x" title={label}>{label}</div>
                              <div className="chart-bar-area">
                                <div className="chart-bar" style={{ width: `${widthPct}%` }}>
                                  <span className="bar-value">{delayNum}s</span>
                                </div>
                              </div>
                            </div>
                          );
                        })}
                      </div>

                      <div className="table-responsive scroll-x">
                        <table className="bento-table" style={{ minWidth: '900px' }}>
                          <thead>
                            <tr>
                              <th>Hop</th>
                              <th>Delay</th>
                              <th>From</th>
                              <th>By</th>
                              <th>With</th>
                              <th>Time (UTC)</th>
                              <th>Blacklist</th>
                            </tr>
                          </thead>
                          <tbody>
                            {relaysList.map((relay, idx) => (
                              <tr key={idx}>
                                <td><strong>{relay.hop || '-'}</strong></td>
                                <td className="pixel-mono">{relay.delay || '-'}</td>
                                <td className="pixel-mono scroll-x" style={{ maxWidth: '200px' }}>{relay.from || '-'}</td>
                                <td className="pixel-mono scroll-x" style={{ maxWidth: '200px' }}>{relay.by || '-'}</td>
                                <td className="pixel-mono">{relay.with || '-'}</td>
                                <td className="pixel-mono">{relay.time || '-'}</td>
                                <td>
                                  {relay.blacklist ? (
                                    <span className="badge bg-danger">Flagged</span>
                                  ) : (
                                    <span className="badge bg-success">Clean</span>
                                  )}
                                </td>
                              </tr>
                            ))}
                          </tbody>
                        </table>
                      </div>
                    </>
                  )}
                </div>
              </div>

              {/* SECTION 3: SPLIT DASHBOARDS (Breakdown + Basis & Links) */}
              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-card-checklist"></i> Analysis Breakdown</span>
                  <p className="small mb-3">Category basis and reasons for security verification:</p>
                  
                  <div className="d-flex flex-column gap-3">
                    
                    {isSpoofed && evidenceList.map((e, idx) => (
                      <div key={idx} className="bento-list-item" style={{ background: '#f8d7da' }}>
                        <strong className="d-block mb-1"><i className="bi bi-exclamation-triangle-fill text-danger"></i> Spoofing Evidence</strong>
                        <span style={{ fontSize: '0.95rem' }}>{e}</span>
                      </div>
                    ))}

                    <details className="bento-accordion">
                      <summary><i className="bi bi-shield-check"></i> SPF Basis</summary>
                      <div className="accordion-content">
                        <p className="mb-2" style={{ fontSize: '0.95rem' }}>
                          {auth.spf === 'PASS' 
                            ? "The email was sent from an IP address officially authorized by the domain owner's SPF records."
                            : "The sender's IP address is NOT listed in the domain's authorized SPF records."}
                        </p>
                        <div className="header-content-box pixel-mono mt-2">{auth.spf_basis || auth.raw_basis || "No raw SPF basis provided."}</div>
                      </div>
                    </details>

                    <details className="bento-accordion">
                      <summary><i className="bi bi-key"></i> DKIM Basis</summary>
                      <div className="accordion-content">
                        <p className="mb-2" style={{ fontSize: '0.95rem' }}>
                           {auth.dkim === 'PASS' 
                            ? "A valid digital signature was found, proving the email wasn't altered in transit."
                            : "The digital signature is missing, invalid, or broken."}
                        </p>
                        <div className="header-content-box pixel-mono mt-2">{auth.dkim_basis || "No raw DKIM basis provided."}</div>
                      </div>
                    </details>

                    <details className="bento-accordion">
                      <summary><i className="bi bi-diagram-3"></i> DMARC Basis</summary>
                      <div className="accordion-content">
                        <p className="mb-2" style={{ fontSize: '0.95rem' }}>
                           {auth.dmarc === 'PASS' 
                            ? "The visible 'From' address aligns perfectly with the validated SPF/DKIM domains."
                            : "The 'From' address does not match the server it was sent from, indicating potential spoofing."}
                        </p>
                        <div className="header-content-box pixel-mono mt-2">{auth.dmarc_basis || "No raw DMARC basis provided."}</div>
                      </div>
                    </details>

                  </div>
                </div>
              </div>

              <div className="col-md-6">
                <div className="bento-card h-100 p-4">
                  <span className="handwriting-text d-block mb-3 fs-4"><i className="bi bi-link-45deg"></i> Embedded Links Analysis</span>
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
                                  {vt.malicious} MALICIOUS <i className="bi bi-box-arrow-up-right ms-1"></i>
                                </button>
                              ) : (
                                <span className="bento-pill safe-card text-nowrap text-white" style={{ border: 'none' }}>
                                  <i className="bi bi-check-circle"></i> 0 MALICIOUS
                                </span>
                              )
                            ) : (
                              <span className="bento-pill outline-pill text-nowrap">UNSCORED</span>
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              </div>

              {/* SECTION 4: REMAINING RAW HEADERS */}
              <div className="col-12">
                <div className="bento-card p-4">
                  <div className="d-flex align-items-center gap-2 mb-4">
                    <span className="handwriting-text m-0 fs-4"><i className="bi bi-braces"></i> Technical Raw Headers</span>
                    <button className="help-icon" onClick={() => openEduModal('headers')}><i className="bi bi-question-lg"></i></button>
                  </div>
                  
                  <div className="row g-3">
                    {remainingHeaders.map((hdr, idx) => (
                      <div key={idx} className="col-md-6 col-lg-4">
                        <div className="bento-list-item h-100">
                          <strong className="d-block mb-1 text-truncate" title={hdr.name}>{hdr.name}</strong>
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
                <button onClick={() => setModalState({ ...modalState, isOpen: false })} className="bento-btn bento-btn-icon"><i className="bi bi-x-lg"></i></button>
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