import type { EmailAnalysis } from '@/types';

/**
 * Lightweight pure-JS ZIP file builder for client-side evidence package archiving.
 * Creates standard PKZIP archives without external runtime dependencies.
 */
class SimpleZip {
  private files: Array<{ name: string; data: Uint8Array }> = [];

  addFile(name: string, content: string | Uint8Array) {
    const data = typeof content === 'string' ? new TextEncoder().encode(content) : content;
    this.files.push({ name, data });
  }

  private crc32(data: Uint8Array): number {
    let crc = 0 ^ -1;
    for (let i = 0; i < data.length; i++) {
      crc = (crc >>> 8) ^ CRC_TABLE[(crc ^ data[i]) & 0xff];
    }
    return (crc ^ -1) >>> 0;
  }

  generate(): Uint8Array {
    let fileEntries: Uint8Array[] = [];
    let centralDirEntries: Uint8Array[] = [];
    let offset = 0;

    for (const file of this.files) {
      const nameBytes = new TextEncoder().encode(file.name);
      const crc = this.crc32(file.data);
      const size = file.data.length;

      // Local file header (30 bytes + filename)
      const localHeader = new Uint8Array(30 + nameBytes.length);
      const view = new DataView(localHeader.buffer);
      view.setUint32(0, 0x04034b50, true); // Local file header signature
      view.setUint16(4, 20, true);         // Version needed (2.0)
      view.setUint16(6, 0, true);          // Flags
      view.setUint16(8, 0, true);          // Compression (stored)
      view.setUint16(10, 0, true);         // Time
      view.setUint16(12, 0, true);         // Date
      view.setUint32(14, crc, true);       // CRC32
      view.setUint32(18, size, true);      // Compressed size
      view.setUint32(22, size, true);      // Uncompressed size
      view.setUint16(26, nameBytes.length, true); // File name length
      view.setUint16(28, 0, true);         // Extra field length
      localHeader.set(nameBytes, 30);

      // Central directory header (46 bytes + filename)
      const cdHeader = new Uint8Array(46 + nameBytes.length);
      const cdView = new DataView(cdHeader.buffer);
      cdView.setUint32(0, 0x02014b50, true); // Central directory signature
      cdView.setUint16(4, 20, true);         // Version made by
      cdView.setUint16(6, 20, true);         // Version needed
      cdView.setUint16(8, 0, true);          // Flags
      cdView.setUint16(10, 0, true);         // Compression (0 = stored)
      cdView.setUint16(12, 0, true);         // Time
      cdView.setUint16(14, 0, true);         // Date
      cdView.setUint32(16, crc, true);       // CRC32
      cdView.setUint32(20, size, true);      // Compressed size
      cdView.setUint32(24, size, true);      // Uncompressed size
      cdView.setUint16(28, nameBytes.length, true); // Name length
      cdView.setUint16(30, 0, true);         // Extra length
      cdView.setUint16(32, 0, true);         // Comment length
      cdView.setUint16(34, 0, true);         // Disk start
      cdView.setUint16(36, 0, true);         // Internal attributes
      cdView.setUint32(38, 0, true);         // External attributes
      cdView.setUint32(42, offset, true);    // Offset of local header
      cdHeader.set(nameBytes, 46);

      fileEntries.push(localHeader, file.data);
      centralDirEntries.push(cdHeader);
      offset += localHeader.length + file.data.length;
    }

    const cdOffset = offset;
    let cdSize = 0;
    for (const c of centralDirEntries) cdSize += c.length;

    // End of central directory record (22 bytes)
    const eocd = new Uint8Array(22);
    const eocdView = new DataView(eocd.buffer);
    eocdView.setUint32(0, 0x06054b50, true); // EOCD signature
    eocdView.setUint16(4, 0, true);          // Disk number
    eocdView.setUint16(6, 0, true);          // Start disk
    eocdView.setUint16(8, this.files.length, true);  // Disk entries
    eocdView.setUint16(10, this.files.length, true); // Total entries
    eocdView.setUint32(12, cdSize, true);    // Size of central dir
    eocdView.setUint32(16, cdOffset, true);  // Offset of central dir
    eocdView.setUint16(20, 0, true);         // Comment length

    // Assemble total package
    const totalSize = offset + cdSize + 22;
    const finalZip = new Uint8Array(totalSize);
    let pos = 0;
    for (const chunk of fileEntries) {
      finalZip.set(chunk, pos);
      pos += chunk.length;
    }
    for (const chunk of centralDirEntries) {
      finalZip.set(chunk, pos);
      pos += chunk.length;
    }
    finalZip.set(eocd, pos);

    return finalZip;
  }
}

// Pre-computed CRC32 Table
const CRC_TABLE = new Uint32Array(256);
for (let i = 0; i < 256; i++) {
  let c = i;
  for (let j = 0; j < 8; j++) {
    c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
  }
  CRC_TABLE[i] = c >>> 0;
}

/**
 * Generates and downloads a complete forensic investigation package.
 */
export async function exportInvestigationPackage(analysis: EmailAnalysis): Promise<void> {
  const caseId = analysis.evidence.evidenceId || `ST-CASE-${Date.now()}`;
  const zip = new SimpleZip();
  const folder = `SentinelTrace_Case_${caseId}/`;

  // 1. original_email.eml
  const rawEmailContent = analysis.rawHeaders + '\n\n' + analysis.bodyPreview;
  zip.addFile(`${folder}original_email.eml`, rawEmailContent);

  // 2. forensic_report.html
  const htmlReport = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelTrace Forensic Investigation Report - ${caseId}</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #020617; color: #f8fafc; padding: 30px; line-height: 1.6; }
    h1, h2 { color: #22d3ee; }
    .card { background: #080e21; border: 1px solid #1e293b; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
    .badge { display: inline-block; padding: 4px 8px; border-radius: 4px; font-weight: bold; font-family: monospace; }
    .critical { background: #ef444420; color: #ef4444; border: 1px solid #ef4444; }
    table { width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }
    th, td { text-align: left; padding: 8px 12px; border-bottom: 1px solid #1e293b; }
    th { color: #94a3b8; }
  </style>
</head>
<body>
  <h1>SENTINELTRACE DIGITAL FORENSIC INVESTIGATION REPORT</h1>
  <div class="card">
    <h2>Case Identification</h2>
    <p><strong>Evidence ID:</strong> ${caseId}</p>
    <p><strong>SHA-256 Digest:</strong> ${analysis.evidence.sha256}</p>
    <p><strong>Threat Score:</strong> <span class="badge critical">${analysis.score.total}/100 (${analysis.score.level})</span></p>
    <p><strong>Classification:</strong> ${analysis.assessment.classification}</p>
    <p><strong>Narrative:</strong> ${analysis.assessment.narrative}</p>
  </div>
  <div class="card">
    <h2>Extracted Indicators of Compromise</h2>
    <table>
      <thead><tr><th>Type</th><th>Value</th><th>Risk</th><th>Reputation</th></tr></thead>
      <tbody>
        ${analysis.iocs.map(i => `<tr><td>${i.type}</td><td>${i.value}</td><td>${i.risk}</td><td>${i.reputation}</td></tr>`).join('')}
      </tbody>
    </table>
  </div>
</body>
</html>`;
  zip.addFile(`${folder}forensic_report.html`, htmlReport);

  // 3. forensic_report.json
  zip.addFile(`${folder}forensic_report.json`, JSON.stringify(analysis, null, 2));

  // 4. indicators.json
  zip.addFile(`${folder}indicators.json`, JSON.stringify(analysis.iocs, null, 2));

  // 5. stix_bundle.json
  const stixBundle = {
    type: 'bundle',
    id: `bundle--${analysis.evidence.evidenceId.toLowerCase()}`,
    spec_version: '2.1',
    objects: analysis.iocs.map(ioc => ({
      type: 'indicator',
      spec_version: '2.1',
      id: `indicator--${ioc.id}`,
      created: new Date().toISOString(),
      modified: new Date().toISOString(),
      name: `${ioc.type}: ${ioc.value}`,
      pattern: `[${ioc.type.toLowerCase()}-addr:value = '${ioc.value}']`,
      pattern_type: 'stix',
      valid_from: new Date().toISOString(),
    })),
  };
  zip.addFile(`${folder}stix_bundle.json`, JSON.stringify(stixBundle, null, 2));

  // 6. header_analysis.json
  zip.addFile(`${folder}header_analysis.json`, JSON.stringify(analysis.headers, null, 2));

  // 7. authentication_results.json
  zip.addFile(`${folder}authentication_results.json`, JSON.stringify(analysis.authentication, null, 2));

  // 8. relay_chain.json
  zip.addFile(`${folder}relay_chain.json`, JSON.stringify(analysis.relayChain, null, 2));

  // 9. geolocation.json
  zip.addFile(`${folder}geolocation.json`, JSON.stringify(analysis.originAssessment, null, 2));

  // 10. campaign.json
  zip.addFile(`${folder}campaign.json`, JSON.stringify({
    campaignId: analysis.campaignId || 'UNCORRELATED',
    status: analysis.campaignId ? 'CORRELATED' : 'ISOLATED',
    analyzedAt: analysis.analyzedAt,
  }, null, 2));

  // 11. evidence_manifest.json (Cryptographic Manifest)
  const manifest = {
    caseId,
    evidenceId: analysis.evidence.evidenceId,
    targetFilename: analysis.filename,
    sha256: analysis.evidence.sha256,
    fileSizeBytes: analysis.evidence.sizeBytes,
    acquisitionTimestamp: analysis.evidence.acquiredAt,
    analystId: analysis.evidence.analystId,
    manifestGeneratedAt: new Date().toISOString(),
    integrityStatus: analysis.evidence.integrity,
  };
  zip.addFile(`${folder}evidence_manifest.json`, JSON.stringify(manifest, null, 2));

  // 12. chain_of_custody.json
  zip.addFile(`${folder}chain_of_custody.json`, JSON.stringify(analysis.evidence.custody, null, 2));

  // Build ZIP archive
  const zipData = zip.generate();
  const blob = new Blob([zipData], { type: 'application/zip' });
  const downloadUrl = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = downloadUrl;
  anchor.download = `SentinelTrace_Case_${caseId}.zip`;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(downloadUrl);
}
