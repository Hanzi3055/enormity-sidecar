const PDFDocument = require('pdfkit');
const archiver = require('archiver');

const PAGE = { margin: 36, width: 842, height: 595 };
const WATERMARK = 'Enormity Tech R&D';

function fmt(value) {
  if (value === null || value === undefined) return '';
  if (value instanceof Date) return value.toISOString().replace('T', ' ').slice(0, 19);
  return String(value);
}

function drawHeader(doc, title, meta) {
  doc.rect(0, 0, PAGE.width, 74).fill('#f7f9fc');
  doc.fillColor('#1f2937').font('Helvetica-Bold').fontSize(16).text('KEMENTERIAN PENDIDIKAN MALAYSIA', PAGE.margin, 20);
  doc.fontSize(9).fillColor('#64748b').text('Sistem Pemantauan Rondaan Keselamatan - Enormity Nexus', PAGE.margin, 42);
  doc.fillColor('#0f172a').font('Helvetica-Bold').fontSize(13).text(title, PAGE.margin, 86, { width: PAGE.width - PAGE.margin * 2, align: 'center' });
  doc.font('Helvetica').fontSize(8).fillColor('#334155');
  const left = PAGE.margin;
  const top = 116;
  doc.text(`Nama Syarikat: ${fmt(meta.companyName || '-')}`, left, top);
  doc.text(`Tempoh Laporan: ${fmt(meta.period || meta.date || '-')}`, left, top + 14);
  doc.text(`Tarikh Jana: ${new Date().toISOString().slice(0, 10)}`, PAGE.width - 220, top);
  doc.text(`Rujukan: ENO-KPM-${fmt(meta.reportCode || 'REPORT')}`, PAGE.width - 220, top + 14);
  doc.moveTo(PAGE.margin, top + 34).lineTo(PAGE.width - PAGE.margin, top + 34).strokeColor('#cbd5e1').stroke();
}

function fitText(doc, text, x, y, width, height, options = {}) {
  doc.font(options.bold ? 'Helvetica-Bold' : 'Helvetica').fontSize(options.size || 7).fillColor(options.color || '#0f172a');
  doc.text(fmt(text), x + 4, y + 5, { width: width - 8, height: height - 8, ellipsis: true, align: options.align || 'left' });
}

function drawTable(doc, columns, rows, yStart) {
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

function drawFooter(doc) {
  const page = doc.bufferedPageRange().count;
  doc.font('Helvetica').fontSize(7).fillColor('#94a3b8')
    .text(`${WATERMARK} | Dokumen dijana secara automatik | Halaman ${page}`, PAGE.margin, PAGE.height - 32, { width: PAGE.width - PAGE.margin * 2, align: 'center' });
}

function renderReport({ title, reportCode, companyName, period, columns, rows }) {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: 'A4', layout: 'landscape', margin: PAGE.margin, bufferPages: true });
    const chunks = [];
    doc.on('data', (chunk) => chunks.push(chunk));
    doc.on('end', () => resolve(Buffer.concat(chunks)));
    doc.on('error', reject);
    drawHeader(doc, title, { reportCode, companyName, period });
    const y = drawTable(doc, columns, rows, 160);
    drawSignatures(doc, y);
    const range = doc.bufferedPageRange();
    for (let i = range.start; i < range.start + range.count; i += 1) {
      doc.switchToPage(i);
      drawFooter(doc);
    }
    doc.end();
  });
}

async function pkk2({ companyName, month, year, rows }) {
  const columns = [
    { key: 'bil', label: 'Bil', w: 5, align: 'center' },
    { key: 'companyName', label: 'Nama Syarikat Keselamatan', w: 26 },
    { key: 'approvedGuards', label: 'Bilangan Pengawal Diluluskan', w: 16, align: 'center' },
    { key: 'guardsOnDuty', label: 'Bilangan Pengawal Bertugas', w: 16, align: 'center' },
    { key: 'siteCount', label: 'Bilangan Tapak Kawalan', w: 16, align: 'center' },
    { key: 'complianceRate', label: 'Peratusan Pematuhan', w: 15, align: 'center' },
  ];
  return renderReport({ title: 'PKK 2 - LAPORAN RINGKASAN PENGAWAL KESELAMATAN', reportCode: 'PKK2', companyName, period: `${month}/${year}`, columns, rows });
}

async function pkk3({ companyName, date, rows }) {
  const columns = [
    { key: 'bil', label: 'Bil', w: 4, align: 'center' },
    { key: 'guardName', label: 'Nama Pengawal', w: 17 },
    { key: 'icNo', label: 'No. KP', w: 12 },
    { key: 'date', label: 'Tarikh', w: 10, align: 'center' },
    { key: 'clockIn', label: 'Masa Lapor Diri', w: 13, align: 'center' },
    { key: 'clockOut', label: 'Masa Tamat Bertugas', w: 13, align: 'center' },
    { key: 'hoursWorked', label: 'Jumlah Jam Bertugas', w: 12, align: 'center' },
    { key: 'biometric', label: 'Pengesahan Cap Jari', w: 13, align: 'center' },
    { key: 'remarks', label: 'Catatan', w: 14 },
  ];
  return renderReport({ title: 'PKK 3 - REKOD KEHADIRAN PENGAWAL KESELAMATAN', reportCode: 'PKK3', companyName, period: date, columns, rows });
}

async function pkk4({ companyName, date, rows }) {
  const columns = [
    { key: 'bil', label: 'Bil', w: 5, align: 'center' },
    { key: 'guardName', label: 'Nama Pengawal', w: 20 },
    { key: 'guardCode', label: 'Kod Pengawal', w: 14 },
    { key: 'siteName', label: 'Nama Tapak Kawalan', w: 24 },
    { key: 'patrolTime', label: 'Masa Rondaan', w: 18, align: 'center' },
    { key: 'status', label: 'Status', w: 10, align: 'center' },
    { key: 'remarks', label: 'Catatan', w: 20 },
  ];
  return renderReport({ title: 'PKK 4 - REKOD RONDAAN PENGAWAL KESELAMATAN', reportCode: 'PKK4', companyName, period: date, columns, rows });
}

function bundle(res, files) {
  return new Promise((resolve, reject) => {
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.on('error', reject);
    archive.on('end', resolve);
    archive.pipe(res);
    files.forEach((file) => archive.append(file.buffer, { name: file.name }));
    archive.finalize();
  });
}

module.exports = { pkk2, pkk3, pkk4, bundle };
