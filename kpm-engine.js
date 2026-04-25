const PDFDocument = require('pdfkit');
const archiver = require('archiver');

const PAGE = { margin: 36, width: 842, height: 595 };
const WATERMARK = 'Enormity Tech R&D';

function generationTimestamp(value) {
  const now = value instanceof Date ? value : new Date();
  const dd = String(now.getDate()).padStart(2, '0');
  const mm = String(now.getMonth() + 1).padStart(2, '0');
  const yyyy = now.getFullYear();
  const hh = String(now.getHours()).padStart(2, '0');
  const min = String(now.getMinutes()).padStart(2, '0');
  return `${dd}/${mm}/${yyyy} ${hh}:${min}`;
}

function fmt(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return generationTimestamp(value);
  return String(value);
}

function safeRows(rows) {
  return Array.isArray(rows) ? rows.filter(Boolean) : [];
}

function withPdfError(label, producer) {
  return Promise.resolve()
    .then(producer)
    .catch((err) => {
      const wrapped = new Error(`${label} PDF generation failed: ${err.message}`);
      wrapped.cause = err;
      throw wrapped;
    });
}

function drawHeader(doc, title, meta = {}) {
  doc.rect(0, 0, PAGE.width, 74).fill('#f7f9fc');
  doc.rect(PAGE.margin, 16, 66, 42).fillAndStroke('#ffffff', '#94a3b8');
  doc.fillColor('#64748b').font('Helvetica-Bold').fontSize(9).text('LOGO', PAGE.margin + 18, 31);
  doc.fillColor('#1f2937').font('Helvetica-Bold').fontSize(16).text('KEMENTERIAN PENDIDIKAN MALAYSIA', PAGE.margin + 82, 20);
  doc.fontSize(9).fillColor('#64748b').text('Sistem Pemantauan Rondaan Keselamatan - Enormity Nexus', PAGE.margin + 82, 42);
  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(13).text(title, PAGE.margin, 86, { width: PAGE.width - PAGE.margin * 2, align: 'center' });
  doc.font('Helvetica').fontSize(8).fillColor('#334155');
  const left = PAGE.margin;
  const top = 116;
  doc.text(`Nama Syarikat: ${fmt(meta.companyName || '-')}`, left, top);
  doc.text(`Tempoh Laporan: ${fmt(meta.period || meta.date || '-')}`, left, top + 14);
  doc.text(`Tarikh Jana: ${fmt(meta.generatedAt || generationTimestamp())}`, PAGE.width - 220, top);
  doc.text(`Rujukan: ENO-KPM-${fmt(meta.reportCode || 'REPORT')}`, PAGE.width - 220, top + 14);
  doc.moveTo(PAGE.margin, top + 34).lineTo(PAGE.width - PAGE.margin, top + 34).strokeColor('#cbd5e1').stroke();
}

function fitText(doc, text, x, y, width, height, options = {}) {
  doc.font(options.bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(options.size || 7).fillColor(options.color || '#0f172a');
  doc.text(fmt(text), x + 4, y + 5, { width: width - 8, height: height - 8, ellipsis: true, align: options.align || 'left' });
}

function drawTable(doc, columns, rows, yStart) {
  columns = safeRows(columns);
  rows = safeRows(rows);
  if (!columns.length) columns = [{ key: 'message', label: 'Maklumat', w: 1 }];
  const tableWidth = PAGE.width - PAGE.margin * 2;
  const totalWeight = columns.reduce((sum, c) => sum + c.w, 0);
  const widths = columns.map((c) => Math.floor((c.w / totalWeight) * tableWidth));
  widths[widths.length - 1] += tableWidth - widths.reduce((a, b) => a + b, 0);
  let y = yStart;
  const headerH = 30;
  const rowH = 28;
  const drawHeaderRow = () => {
    let x = PAGE.margin;
    doc.rect(PAGE.margin, y, tableWidth, headerH).fill('#e8eef7');
    columns.forEach((col, i) => {
      doc.rect(x, y, widths[i], headerH).strokeColor('#94a3b8').stroke();
      fitText(doc, col.label, x, y, widths[i], headerH, { bold: true, size: 7, align: 'center' });
      x += widths[i];
    });
    y += headerH;
  };
  drawHeaderRow();
  rows.forEach((row, index) => {
    if (y + rowH > PAGE.height - 76) {
      drawFooter(doc);
      doc.addPage({ size: 'A4', layout: 'landscape', margin: PAGE.margin });
      y = 50;
      drawHeaderRow();
    }
    let x = PAGE.margin;
    if (index % 2 === 0) doc.rect(PAGE.margin, y, tableWidth, rowH).fill('#fbfdff');
    columns.forEach((col, i) => {
      doc.rect(x, y, widths[i], rowH).strokeColor('#cbd5e1').stroke();
      fitText(doc, row[col.key], x, y, widths[i], rowH, { align: col.align || 'left' });
      x += widths[i];
    });
    y += rowH;
  });
  return y;
}

function drawSignatures(doc, y) {
  const top = Math.min(y + 26, PAGE.height - 118);
  const boxW = 250;
  doc.font('Helvetica').fontSize(8).fillColor('#0f172a');
  doc.text('Disediakan Oleh:', PAGE.margin, top);
  doc.text('Disahkan Oleh:', PAGE.width - PAGE.margin - boxW, top);
  doc.moveTo(PAGE.margin, top + 44).lineTo(PAGE.margin + boxW, top + 44).strokeColor('#334155').stroke();
  doc.moveTo(PAGE.width - PAGE.margin - boxW, top + 44).lineTo(PAGE.width - PAGE.margin, top + 44).strokeColor('#334155').stroke();
  doc.text('Pegawai Keselamatan', PAGE.margin, top + 50);
  doc.text('Penyelia', PAGE.width - PAGE.margin - boxW, top + 50);
}

function drawSummary(doc, summary, y) {
  if (!summary) return y;
  const top = Math.min(y + 18, PAGE.height - 150);
  doc.rect(PAGE.margin, top, PAGE.width - PAGE.margin * 2, 26).fill('#eef4fb');
  doc.font('Helvetica-Bold').fontSize(8).fillColor('#0f172a')
    .text(summary, PAGE.margin + 10, top + 9, { width: PAGE.width - PAGE.margin * 2 - 20, align: 'left' });
  return top + 30;
}

function drawFooter(doc, pageNumber, totalPages, generatedAt) {
  const page = doc.bufferedPageRange().count;
  doc.font('Helvetica').fontSize(7).fillColor('#94a3b8')
    .text(`${WATERMARK} | Dijana pada: ${generatedAt || generationTimestamp()} | Muka Surat ${pageNumber} dari ${totalPages || page}`, PAGE.margin, PAGE.height - 32, { width: PAGE.width - PAGE.margin * 2, align: 'center' });
}

function renderReport({ title, reportCode, companyName, period, columns, rows, summary }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: PAGE.margin, bufferPages: true });
    const chunks = [];
    const generatedAt = generationTimestamp();
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    const safeReportRows = safeRows(rows);
    drawHeader(doc, title || 'Laporan KPM', { reportCode, companyName: companyName || '-', period: period || '-', generatedAt });
    let y = drawTable(doc, columns, safeReportRows.length ? safeReportRows : [{ message: 'Tiada rekod untuk tempoh laporan.' }], 160);
    y = drawSummary(doc, summary, y);
    drawSignatures(doc, y);
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i += 1) {
      doc.switchToPage(i);
      drawFooter(doc, i - range.start + 1, range.count, generatedAt);
    }
    doc.end();
  });
}

async function pkk2({ companyName = '-', month = '-', year = '-', rows = [] } = {}) {
  return withPdfError('PKK2', () => {
  const columns = [
    { key: 'bil', label: 'Bil', w: 5, align: 'center' },
    { key: 'companyName', label: 'Nama Syarikat Keselamatan', w: 26 },
    { key: 'approvedGuards', label: 'Bilangan Pengawal Diluluskan', w: 16, align: 'center' },
    { key: 'guardsOnDuty', label: 'Bilangan Pengawal Bertugas', w: 16, align: 'center' },
    { key: 'siteCount', label: 'Bilangan Tapak Kawalan', w: 16, align: 'center' },
    { key: 'complianceRate', label: 'Peratusan Pematuhan', w: 12, align: 'center' },
    { key: 'kpmGrade', label: 'Gred KPM', w: 9, align: 'center' },
  ];
  return renderReport({ title: 'PKK 2 - LAPORAN RINGKASAN PENGAWAL KESELAMATAN', reportCode: 'PKK2', companyName, period: `${month}/${year}`, columns, rows });
  });
}

async function pkk3({ companyName = '-', date = '-', rows = [] } = {}) {
  return withPdfError('PKK3', () => {
  const columns = [
    { key: 'bil', label: 'Bil', w: 4, align: 'center' },
    { key: 'guardName', label: 'Nama Pengawal Keselamatan', w: 19 },
    { key: 'icNo', label: 'No. KP', w: 12 },
    { key: 'date', label: 'Tarikh', w: 10, align: 'center' },
    { key: 'clockIn', label: 'Masa Lapor Diri', w: 13, align: 'center' },
    { key: 'clockOut', label: 'Masa Tamat Bertugas', w: 13, align: 'center' },
    { key: 'hoursWorked', label: 'Jumlah Jam Bertugas', w: 12, align: 'center' },
    { key: 'biometric', label: 'Pengesahan Cap Jari', w: 13, align: 'center' },
    { key: 'remarks', label: 'Catatan', w: 14 },
  ];
  return renderReport({ title: 'PKK 3 - REKOD KEHADIRAN PENGAWAL KESELAMATAN', reportCode: 'PKK3', companyName, period: date, columns, rows });
  });
}

async function pkk4({ companyName = '-', date = '-', rows = [] } = {}) {
  return withPdfError('PKK4', () => {
  rows = safeRows(rows);
  const completed = rows.filter((row) => String(row.status || '').toUpperCase() === 'SELESAI').length;
  const missed = Math.max(rows.length - completed, 0);
  const compliance = rows.length > 0 ? ((completed / rows.length) * 100).toFixed(2) : '0.00';
  const columns = [
    { key: 'bil', label: 'Bil', w: 5, align: 'center' },
    { key: 'guardName', label: 'Nama Pengawal Keselamatan', w: 22 },
    { key: 'siteName', label: 'Tapak Kawalan', w: 24 },
    { key: 'patrolTime', label: 'Masa Rondaan', w: 18, align: 'center' },
    { key: 'status', label: 'Status Rondaan', w: 12, align: 'center' },
    { key: 'deviceCode', label: 'Kod Peranti', w: 15, align: 'center' },
    { key: 'remarks', label: 'Catatan', w: 18 },
  ];
  const summary = `Total Pusat Kawalan: ${rows.length} | Selesai: ${completed} | Terlepas: ${missed} | Pematuhan: ${compliance}%`;
  return renderReport({ title: 'PKK 4 - REKOD RONDAAN PENGAWAL KESELAMATAN', reportCode: 'PKK4', companyName, period: date, columns, rows, summary });
  });
}

async function dailyScorecard({ companyName, date, scorecard = {}, topGuards = [], unresolvedSos = [] }) {
  return withPdfError('Daily scorecard', () => new Promise((resolve, reject) => {
    topGuards = safeRows(topGuards);
    unresolvedSos = safeRows(unresolvedSos);
    scorecard = scorecard || {};
    const doc = new PDFDocument({ size: 'A4', margin: 36 });
    const chunks = [];
    const generatedAt = generationTimestamp();
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);

    doc.rect(0, 0, 595, 110).fill('#0f172a');
    doc.fillColor('#ffffff').font('Helvetica-Bold').fontSize(18).text('ENORMITY DAILY SCORECARD', 36, 28);
    doc.fontSize(10).fillColor('#cbd5e1').text(`Nama Syarikat: ${companyName || '-'}`, 36, 58);
    doc.text(`Tarikh: ${date || '-'}`, 36, 74);
    doc.text(`Gred KPM: ${scorecard.kpmGrade || '-'}`, 400, 58);
    doc.text(`Dijana pada: ${generatedAt}`, 400, 74);

    const cards = [
      { label: 'Jumlah Imbasan', value: scorecard.totalScans || 0 },
      { label: 'Pengawal Aktif', value: scorecard.activeGuards || 0 },
      { label: 'Tapak Aktif', value: scorecard.activeSites || 0 },
      { label: 'Alarm SOS', value: scorecard.sosAlarms || 0 },
      { label: 'Kadar Pematuhan', value: `${scorecard.complianceRate || 0}%` },
      { label: 'Gred', value: scorecard.kpmGrade || '-' },
    ];
    cards.forEach((card, index) => {
      const x = 36 + ((index % 3) * 174);
      const y = 136 + (Math.floor(index / 3) * 88);
      doc.roundedRect(x, y, 160, 68, 12).fillAndStroke('#f8fafc', '#cbd5e1');
      doc.fillColor('#64748b').font('Helvetica').fontSize(9).text(card.label, x + 12, y + 14);
      doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(18).text(String(card.value), x + 12, y + 32);
    });

    doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(12).text('Top 3 Pengawal Hari Ini', 36, 330);
    topGuards.forEach((row, index) => {
      doc.font('Helvetica').fontSize(10).text(`${index + 1}. ${fmt(row.guardName)} - ${fmt(row.totalScans)} imbasan`, 48, 352 + (index * 18));
    });

    doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(12).text('SOS Belum Selesai', 320, 330);
    if (!unresolvedSos.length) {
      doc.font('Helvetica').fontSize(10).text('Tiada alarm SOS belum selesai.', 332, 352);
    } else {
      unresolvedSos.slice(0, 5).forEach((row, index) => {
        doc.font('Helvetica').fontSize(10).text(`${index + 1}. ${fmt(row.guardName)} | ${fmt(row.siteName)} | ${fmt(row.happenTime)}`, 332, 352 + (index * 18), { width: 220 });
      });
    }

    drawFooter(doc, 1, 1, generatedAt);
    doc.end();
  }));
}

function bundle(res, files) {
  return new Promise((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', reject);
    archive.on('end', resolve);
    archive.pipe(res);
    safeRows(files).forEach((file, index) => {
      const name = file.name || `report-${index + 1}.pdf`;
      const buffer = Buffer.isBuffer(file.buffer) ? file.buffer : Buffer.from(String(file.buffer || ''));
      archive.append(buffer, { name });
    });
    archive.finalize();
  });
}

module.exports = { pkk2, pkk3, pkk4, dailyScorecard, bundle };
