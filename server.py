import http.server
import socketserver
import json
import os
import time
import io
import base64
import urllib.parse
from pathlib import Path

POC_UUID = "3fa85f64-5717-4562-b3fc-2c963f66afa6"

# Generación de QR en memoria
import qrcode

# Criptografía y PDFs
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature, ValidationContext
from asn1crypto import x509 as asn1_x509, pem as asn1_pem

WORKSPACE = Path(__file__).parent
CERTS_DIR = WORKSPACE / "certs"
OUTPUT_DIR = WORKSPACE / "output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
PORT = int(os.environ.get("PORT", 8000))

# Pre-cargar y cachear certificado CA para validación instantánea
with open(CERTS_DIR / "ca_cert.pem", "rb") as _cf:
    _, _, _der_bytes = asn1_pem.unarmor(_cf.read())
    CA_CERT = asn1_x509.Certificate.load(_der_bytes)
VAL_CTX = ValidationContext(trust_roots=[CA_CERT], allow_fetching=False)

# Pre-cargar SimpleSigners en memoria para evitar leer archivos PEM en cada clic
SIGNER_INSTANCES = {
    "alice": signers.SimpleSigner.load(
        key_file=str(CERTS_DIR / "alice_key.pem"),
        cert_file=str(CERTS_DIR / "alice_cert.pem"),
    ),
    "bob": signers.SimpleSigner.load(
        key_file=str(CERTS_DIR / "bob_key.pem"),
        cert_file=str(CERTS_DIR / "bob_cert.pem"),
    )
}
QR_CACHE = {}

# 10 Firmantes Oficiales para demostración de escalabilidad y adaptación
SIGNERS_DATA = [
    {
        "id": "signer_1",
        "name": "HECTOR OSMEL MENDEZ LOPEZ",
        "cargo": "Jefe de departamento",
        "fecha": "2026.08.25 18:55:09 UTC",
        "cert_prefix": "alice",
        "hash_b64": "i7qeZhAJSpGcyqo4V+OSqPBsoZL8yv3bQqJTc4+C78x5k+CSIUJ1MqCZLCve"
    },
    {
        "id": "signer_2",
        "name": "SERGIO SAUL RAMIREZ LOPEZ",
        "cargo": "Jefe de departamento",
        "fecha": "2026.08.25 19:05:45 UTC",
        "cert_prefix": "bob",
        "hash_b64": "O1lqNn7nICPREUI5QCq6KYVcl2Wergic+390CgUVdPuOYmGde4tJY0bU+jl9"
    },
    {
        "id": "signer_3",
        "name": "FELICIANO NIVARDO MARTINEZ PEREZ",
        "cargo": "Jefe de departamento",
        "fecha": "2026.08.25 19:15:33 UTC",
        "cert_prefix": "alice",
        "hash_b64": "S6wRgr2+MM06iiLUoEaHouQ/JPz34cxw1RKMAviFdC/+YVpxDR9kRh1iFAUHj71M1V/"
    },
    {
        "id": "signer_4",
        "name": "GABRIELA GUADALUPE MERINO LUNA",
        "cargo": "Director General",
        "fecha": "2026.08.26 09:23:23 UTC",
        "cert_prefix": "bob",
        "hash_b64": "KNcEBeEtrkbsz5m5lWet3D5xNgSHEw1i/hzlV3zKrRANri+jpulfS/jDWmVwEKNQT6+0ErFndw5v44qQe+Sz/kB4Hj8jcLP8cW/gBCsKspOuaJV6S8+/Yxo1vROMdWezTtGjuJtB0Jj+wGeWmkoKdqRq0bg=="
    },
    {
        "id": "signer_5",
        "name": "MARIA ELENA ROBLERO SANTIZ",
        "cargo": "Directora de Asuntos Jurídicos",
        "fecha": "2026.08.26 09:40:12 UTC",
        "cert_prefix": "alice",
        "hash_b64": "w91jKnLxP93mZ/vAqKlm38s+Lq1mNv8f72lPqQ=="
    },
    {
        "id": "signer_6",
        "name": "CARLOS ALBERTO SOLIS MORALES",
        "cargo": "Coordinador de Auditoría",
        "fecha": "2026.08.26 09:55:01 UTC",
        "cert_prefix": "bob",
        "hash_b64": "m930qLzOp81nVxLqk120pPqW7m8+J19kLl018z=="
    },
    {
        "id": "signer_7",
        "name": "ANA PATRICIA DOMINGUEZ CRUZ",
        "cargo": "Subdirectora de Egresos",
        "fecha": "2026.08.26 10:10:44 UTC",
        "cert_prefix": "alice",
        "hash_b64": "zP1kL09qW82mLxKpq93nVxL120p8+Mm89J1kL=="
    },
    {
        "id": "signer_8",
        "name": "LUIS ENRIQUE CASTILLO VAZQUEZ",
        "cargo": "Jefe de Unidad de Planeación",
        "fecha": "2026.08.26 10:25:30 UTC",
        "cert_prefix": "bob",
        "hash_b64": "L120p8+Mm89J1kLzP1kL09qW82mLxKpq93nVx=="
    },
    {
        "id": "signer_9",
        "name": "VALERIA ITZEL RIOS FUENTES",
        "cargo": "Titular de Control Interno",
        "fecha": "2026.08.26 10:40:15 UTC",
        "cert_prefix": "alice",
        "hash_b64": "kq93nVxL120p8+Mm89J1kLzP1kL09qW82mLxK=="
    },
    {
        "id": "signer_10",
        "name": "ROBERTO ANTONIO VELASCO GOMEZ",
        "cargo": "Secretario de Finanzas y Administración",
        "fecha": "2026.08.26 11:00:00 UTC",
        "cert_prefix": "bob",
        "hash_b64": "82mLxKpq93nVxL120p8+Mm89J1kLzP1kL09qW=="
    }
]

STATE = {
    "target_total_signers": 4, # Número elegido de firmantes (ej. 1 a 10)
    "signed_count": 0, # Cuántos han firmado
    "visible_signatures": True, # Firmas visibles (True = se muestra bloque de firmantes, False = se oculta)
    "show_individual_qrs": False, # Opción dinámica para mostrar/ocultar los QR de cada firmante
    "current_file": None,
    "is_tampered": False,
    "log": []
}

def log_event(msg):
    STATE["log"].append(f"[{time.strftime('%H:%M:%S')}] {msg}")

def get_qr_base64(text: str, box_size=4) -> str:
    cache_key = f"{text}_{box_size}"
    if cache_key in QR_CACHE:
        return QR_CACHE[cache_key]
    qr = qrcode.QRCode(
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=box_size,
        border=2
    )
    qr.add_data(text)
    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    try:
        # pyrefly: ignore [unexpected-keyword]
        img.save(buf, format="PNG")
    except TypeError:
        img.save(buf)
    res = base64.b64encode(buf.getvalue()).decode("utf-8")
    QR_CACHE[cache_key] = res
    return res

def reset_demo(new_total=None):
    if new_total is not None:
        STATE["target_total_signers"] = max(1, min(10, int(new_total)))
    STATE["signed_count"] = 0
    STATE["show_individual_qrs"] = False
    STATE["current_file"] = None
    STATE["is_tampered"] = False
    STATE["log"] = [f"[{time.strftime('%H:%M:%S')}] Sistema reiniciado a estado original con {STATE['target_total_signers']} firmantes."]
    return get_current_info()

def set_signers_count(count: int):
    STATE["target_total_signers"] = max(1, min(10, int(count)))
    return reset_demo(STATE["target_total_signers"])

def set_visible_signatures(visible: bool):
    STATE["visible_signatures"] = bool(visible)
    mode_str = "VISIBLES" if STATE["visible_signatures"] else "OCULTAS / INVISIBLES"
    log_event(f"Configuración visual cambiada: Firmas {mode_str}.")
    return get_current_info()

def toggle_individual_qrs():
    STATE["show_individual_qrs"] = not STATE["show_individual_qrs"]
    mode_str = "ACTIVADOS (Estilo con QR por firmante)" if STATE["show_individual_qrs"] else "DESACTIVADOS (Estilo Texto Limpio)"
    log_event(f"Configuración visual cambiada: QRs individuales {mode_str}.")
    return get_current_info()

def create_base_doc():
    filepath = OUTPUT_DIR / "oficio_oficial_v0.pdf"
    c = canvas.Canvas(str(filepath), pagesize=A4)
    # Dimensiones A4: 595.27 x 841.89 puntos
    
    # Encabezado institucional
    c.setFont("Helvetica-Bold", 12)
    c.drawString(50, 780, "GOBIERNO CONSTITUCIONAL - DICTAMEN DE AUTORIZACIÓN")
    c.setFont("Helvetica", 9)
    c.drawString(50, 765, "Folio de Trámite: EXP-2026-9942-AG | Tipo de Documento: Oficio Resolutivo")
    c.line(50, 755, 545, 755)
    
    # Contenido del oficio
    c.setFont("Helvetica-Bold", 11)
    c.drawString(50, 720, "ASUNTO: RESOLUCIÓN Y VALIDACIÓN DE EXPEDIENTE ADMINISTRATIVO")
    c.setFont("Helvetica", 9.5)
    c.drawString(50, 690, "Por medio de la presente, se emite formal dictamen técnico y financiero respecto a las obras")
    c.drawString(50, 675, "y servicios asignados al presente ejercicio presupuestal. El presente acto surtirá efectos")
    c.drawString(50, 660, "legales plenos una vez completada la cadena de firmas electrónicas avanzadas correspondientes.")
    c.drawString(50, 630, "Los firmantes certifican la autenticidad, integridad y no repudio del contenido.")
    
    # Espacio para el pie de multifirma oficial
    c.setStrokeColorRGB(0.8, 0.8, 0.8)
    c.rect(45, 100, 505, 220)
    c.setFont("Helvetica-Oblique", 8)
    c.drawString(55, 305, "Espacio reservado para el Bloque de Multifirmado Electrónico Avanzado...")
    
    c.save()
    STATE["signed_count"] = 0
    STATE["current_file"] = str(filepath)
    STATE["is_tampered"] = False
    log_event(f"Oficio Base A4 creado (v0.pdf - {os.path.getsize(filepath)} bytes). Listo para firmar.")
    return get_current_info()

def sign_next():
    """Aplica la siguiente firma en la cadena de forma 100% incremental."""
    idx = STATE["signed_count"]
    total = STATE["target_total_signers"]
    if idx >= total:
        return get_current_info()
    
    signer_info = SIGNERS_DATA[idx]
    
    if idx == 0:
        input_pdf = OUTPUT_DIR / "oficio_oficial_v0.pdf"
        if not input_pdf.exists():
            create_base_doc()
    else:
        input_pdf = OUTPUT_DIR / f"oficio_oficial_v{idx}.pdf"

    output_pdf = OUTPUT_DIR / f"oficio_oficial_v{idx+1}.pdf"

    signer = SIGNER_INSTANCES[signer_info['cert_prefix']]

    with open(input_pdf, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        # Distribuir visualmente hasta 10 firmas en el PDF en 2 filas
        col = idx % 5
        row = idx // 5
        x1 = 50 + (col * 100)
        y1 = 200 - (row * 60)
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name=f"Firma_{signer_info['id']}",
                box=(x1, y1, x1 + 90, y1 + 50)
            )
        )
        meta = signers.PdfSignatureMetadata(
            field_name=f"Firma_{signer_info['id']}",
            reason=f"Firma Oficial ({signer_info['cargo']})",
            location="Plataforma de Firma Electrónica Avanzada"
        )
        pdf_signer = signers.PdfSigner(meta, signer=signer)
        with open(output_pdf, "wb") as outf:
            pdf_signer.sign_pdf(w, output=outf)

    STATE["signed_count"] += 1
    STATE["current_file"] = str(output_pdf)
    STATE["is_tampered"] = False
    log_event(f"Firma {STATE['signed_count']}/{total} aplicada por {signer_info['name']} ({signer_info['cargo']}). Capa incremental añadida.")
    return get_current_info()

def tamper_file():
    if STATE["signed_count"] == 0:
        sign_next()

    input_pdf = Path(STATE["current_file"])
    output_pdf = OUTPUT_DIR / "oficio_oficial_hackeado.pdf"

    with open(input_pdf, "rb") as f:
        data = bytearray(f.read())

    # Alteramos bytes en el stream del oficio original
    idx = data.find(b"stream\r\n")
    if idx == -1:
        idx = data.find(b"stream\n")
    if idx != -1:
        data[idx + 15] ^= 0xFF
        data[idx + 16] ^= 0xFF

    with open(output_pdf, "wb") as f:
        f.write(data)

    STATE["is_tampered"] = True
    STATE["current_file"] = str(output_pdf)
    log_event("ALERTA DE SEGURIDAD: Se alteró el texto del dictamen base. Los sellos criptográficos deben invalidarse.")
    return get_current_info()

def get_current_info():
    target_signers = SIGNERS_DATA[:STATE["target_total_signers"]]
    if not STATE["current_file"] or not os.path.exists(STATE["current_file"]):
        signers_view = []
        for i, s in enumerate(target_signers):
            signers_view.append({
                **s,
                "signed": False,
                "qr_b64": None
            })
        return {
            "signed_count": STATE["signed_count"],
            "total_signers": STATE["target_total_signers"],
            "visible_signatures": STATE["visible_signatures"],
            "show_individual_qrs": STATE["show_individual_qrs"],
            "filename": "Sin documento",
            "file_size": 0,
            "eof_count": 0,
            "is_tampered": False,
            "signers": signers_view,
            "signatures_status": [],
            "log": STATE["log"]
        }

    filepath = Path(STATE["current_file"])
    with open(filepath, "rb") as f:
        raw_data = f.read()
        eof_count = raw_data.count(b"%%EOF")
        reader = PdfFileReader(f)

        signatures_status = []
        for i, sig_obj in enumerate(reader.embedded_signatures):
            try:
                status = validate_pdf_signature(sig_obj, signer_validation_context=VAL_CTX)
                is_intact = status.intact
                summary = status.summary()
            except Exception as e:
                is_intact = False
                summary = str(e)

            signatures_status.append({
                "field_name": sig_obj.field_name,
                "intact": is_intact,
                "summary": summary
            })

        # Generar QR para cada firmante activo dentro del límite seleccionado
        signers_view = []
        for i, s in enumerate(target_signers):
            is_active = i < STATE["signed_count"]
            qr_data = f"FIRMA DIGITAL VALIDA:\nNombre: {s['name']}\nCargo: {s['cargo']}\nFecha: {s['fecha']}\nHash: {s['hash_b64'][:30]}..."
            signers_view.append({
                **s,
                "signed": is_active,
                "qr_b64": get_qr_base64(qr_data) if (is_active and STATE["show_individual_qrs"]) else None
            })

        # Concatenar la cadena de hash pura de los firmantes activos
        active_hashes = "".join([s["hash_b64"] for i, s in enumerate(target_signers) if i < STATE["signed_count"]])
        
        # QR Izquierdo: cadena exacta de hashes acumulados
        left_qr_b64 = get_qr_base64(active_hashes) if active_hashes else None

        # QR Derecho: URL pública de auditoría en vivo del documento
        domain = os.environ.get("RENDER_EXTERNAL_URL", "https://poc-multifirmado.onrender.com")
        audit_url = f"{domain}/visor.html?uuid={POC_UUID}"
        right_qr_b64 = get_qr_base64(audit_url) if active_hashes else None

        return {
            "signed_count": STATE["signed_count"],
            "total_signers": STATE["target_total_signers"],
            "visible_signatures": STATE["visible_signatures"],
            "show_individual_qrs": STATE["show_individual_qrs"],
            "filename": filepath.name,
            "file_size": len(raw_data),
            "eof_count": eof_count,
            "is_tampered": STATE["is_tampered"],
            "signers": signers_view,
            "signatures_status": signatures_status,
            "left_qr_b64": left_qr_b64,
            "right_qr_b64": right_qr_b64,
            "audit_url": audit_url,
            "log": STATE["log"]
        }


def get_audit_document_data():
    target_signers = SIGNERS_DATA[:STATE["target_total_signers"]]
    active_signers = []
    for i, s in enumerate(target_signers):
        if i < STATE["signed_count"]:
            active_signers.append({
                "name": s["name"],
                "rfc": f"XAXX{i+1}00101XXX",
                "status": "Firma Válida" if not STATE["is_tampered"] else "Firma Invalidada",
                "signed_at": s["fecha"],
                "dependency": "Gobierno Constitucional - Dirección General",
                "position": s["cargo"]
            })
    
    active_hashes = "".join([s["hash_b64"] for s in target_signers[:STATE["signed_count"]]])
    doc_status = "vigente" if (not STATE["is_tampered"] and STATE["signed_count"] > 0) else ("revocado" if STATE["is_tampered"] else "pendiente")

    return {
        "document_id": "EXP-2026-9942-AG",
        "document_uuid": POC_UUID,
        "pdf_name": Path(STATE["current_file"]).name if STATE["current_file"] else "oficio_oficial_v0.pdf",
        "doc_type": "Dictamen Resolutivo de Autorización",
        "doc_type_description": "Resolución y validación formal de expediente administrativo emitido con firmas electrónicas avanzadas conforme a PAdES.",
        "signed_at": active_signers[-1]["signed_at"] if active_signers else "Sin firmas",
        "origin_system": "Plataforma de Firma Electrónica Avanzada (PAdES)",
        "origin_dependency": "Gobierno Constitucional - Dirección General de Administración",
        "document_status": doc_status,
        "document_hash": active_hashes if active_hashes else "Sin firmas registradas",
        "downloadable": True if STATE["signed_count"] > 0 else False,
        "timestamp_authority": "PSC Autorizado - Conforme a NOM-151-SCFI-2016 y ETSI EN 319 142 (Timestamp Criptográfico)",
        "signers": active_signers
    }


VISOR_HTML = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
    <title>Validador de Documentos Firmados Electrónicamente Avanzado</title>
    <style>
        :root {
            --gob-primary: #691C32;
            --gob-primary-hover: #521527;
            --gob-gold: #BC955C;
            --gob-dark: #10312B;
            --text-title: #0C231E;
            --text-body: #23272B;
            --text-muted: #545B62;
            --bg-page: #F8F9FA;
            --bg-card: #FFFFFF;
            --border-color: #DEE2E6;
            
            --status-valid-bg: #E8F5E9;
            --status-valid-text: #1B5E20;
            --status-valid-border: #A5D6A7;
            
            --status-invalid-bg: #FFEBEE;
            --status-invalid-text: #B71C1C;
            --status-invalid-border: #EF9A9A;
            
            --status-warning-bg: #FFF8E1;
            --status-warning-text: #E65100;
            --status-warning-border: #FFE082;
        }

        * {
            box-sizing: border-box;
            margin: 0;
            padding: 0;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
            -webkit-tap-highlight-color: transparent;
        }

        body {
            background-color: var(--bg-page);
            color: var(--text-body);
            min-height: 100vh;
            padding: 1rem;
            display: flex;
            justify-content: center;
            align-items: flex-start;
        }

        .container {
            background-color: var(--bg-card);
            max-width: 800px;
            width: 100%;
            padding: 1.75rem;
            border-radius: 6px;
            border: 1px solid var(--border-color);
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.06);
            margin: auto;
        }

        .header-section {
            border-bottom: 2px solid var(--gob-gold);
            padding-bottom: 1rem;
            margin-bottom: 1.5rem;
            text-align: center;
        }

        h1 {
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--gob-primary);
            text-transform: uppercase;
            letter-spacing: 0.03em;
            line-height: 1.4;
            margin-bottom: 0.35rem;
        }

        p.subtitle {
            color: var(--text-muted);
            font-size: 0.85rem;
            line-height: 1.4;
        }

        .status-banner {
            padding: 0.85rem 1rem;
            border-radius: 4px;
            text-align: center;
            font-weight: 700;
            font-size: 0.9rem;
            margin-bottom: 1.5rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        .status-valid {
            background-color: var(--status-valid-bg);
            color: var(--status-valid-text);
            border: 1px solid var(--status-valid-border);
        }

        .status-invalid {
            background-color: var(--status-invalid-bg);
            color: var(--status-invalid-text);
            border: 1px solid var(--status-invalid-border);
        }

        .section-title {
            font-size: 0.9rem;
            font-weight: 700;
            color: var(--gob-primary);
            text-transform: uppercase;
            letter-spacing: 0.05em;
            border-bottom: 1px solid var(--border-color);
            padding-bottom: 0.4rem;
            margin-top: 1.5rem;
            margin-bottom: 0.85rem;
        }

        .data-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 0.65rem;
        }

        @media (min-width: 600px) {
            .data-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .data-item {
            background: #FAFAFA;
            padding: 0.75rem;
            border-radius: 4px;
            border: 1px solid var(--border-color);
        }

        .data-item.full-width {
            grid-column: 1 / -1;
        }

        .data-label {
            font-size: 0.7rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 700;
            letter-spacing: 0.04em;
            margin-bottom: 0.2rem;
        }

        .data-value {
            font-size: 0.85rem;
            color: var(--text-body);
            word-break: break-word;
            line-height: 1.4;
        }

        .data-item.hash-box {
            background: #F4F6F7;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 0.8rem;
        }

        .data-item.hash-box .data-value {
            font-family: inherit;
            word-break: break-all;
        }

        .signer-card {
            background: #FFFFFF;
            border: 1px solid var(--border-color);
            border-left: 4px solid var(--gob-primary);
            border-radius: 4px;
            padding: 0.9rem;
            margin-bottom: 0.75rem;
        }

        .signer-header {
            display: flex;
            flex-direction: column;
            gap: 0.35rem;
            border-bottom: 1px dashed var(--border-color);
            padding-bottom: 0.6rem;
            margin-bottom: 0.6rem;
        }

        @media (min-width: 480px) {
            .signer-header {
                flex-direction: row;
                justify-content: space-between;
                align-items: center;
            }
        }

        .signer-name {
            font-weight: 700;
            color: var(--text-title);
            font-size: 0.9rem;
            text-transform: uppercase;
        }

        .signer-status-badge {
            font-size: 0.75rem;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
            font-weight: 700;
            background-color: var(--status-valid-bg);
            color: var(--status-valid-text);
            border: 1px solid var(--status-valid-border);
            align-self: flex-start;
            text-transform: uppercase;
        }

        .signer-grid {
            display: grid;
            grid-template-columns: 1fr;
            gap: 0.5rem;
        }

        @media (min-width: 540px) {
            .signer-grid {
                grid-template-columns: repeat(2, 1fr);
            }
        }

        .signer-field {
            font-size: 0.8rem;
        }

        .signer-field .field-label {
            font-size: 0.68rem;
            text-transform: uppercase;
            color: var(--text-muted);
            font-weight: 700;
            display: block;
            margin-bottom: 0.15rem;
        }

        .signer-field .field-value {
            color: var(--text-body);
            word-break: break-word;
        }

        .btn-download {
            width: 100%;
            background-color: var(--gob-primary);
            color: #FFFFFF;
            border: 1px solid var(--gob-primary);
            margin-top: 1.5rem;
            padding: 0.85rem;
            font-size: 0.9rem;
            font-weight: 700;
            border-radius: 4px;
            cursor: pointer;
            text-transform: uppercase;
            letter-spacing: 0.04em;
            display: none;
            min-height: 48px;
            transition: background-color 0.2s ease;
        }

        .btn-download:hover {
            background-color: var(--gob-primary-hover);
        }

        .notice {
            font-size: 0.8rem;
            text-align: center;
            margin-top: 1rem;
            padding: 0.75rem;
            border-radius: 4px;
            display: none;
            line-height: 1.4;
        }

        .notice-warning {
            background-color: var(--status-warning-bg);
            color: var(--status-warning-text);
            border: 1px solid var(--status-warning-border);
        }

        .notice-danger {
            background-color: var(--status-invalid-bg);
            color: var(--status-invalid-text);
            border: 1px solid var(--status-invalid-border);
        }

        .loader {
            text-align: center;
            padding: 3rem 1rem;
            color: var(--gob-primary);
            font-weight: 600;
            font-size: 0.85rem;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }

        @media (max-width: 480px) {
            body {
                padding: 0.5rem;
            }
            .container {
                padding: 1rem;
                border-radius: 4px;
            }
            h1 {
                font-size: 1.1rem;
            }
            .data-item {
                padding: 0.6rem;
            }
        }
    </style>
</head>
<body>

    <div class="container">
        <div class="header-section">
            <h1>Auditoría de Documento Firmado Electrónicamente</h1>
            <p class="subtitle">Validación de autenticidad, integridad y estado de firmas digitales</p>
        </div>

        <div id="loader" class="loader">Consultando y verificando firmas y certificados digitales...</div>

        <div id="result-section" style="display: none;">
            <div id="status-banner" class="status-banner"></div>

            <div id="metadata-section">
                <div class="section-title">Información General del Documento</div>
                <div class="data-grid" id="basic-metadata">
                <div class="data-item full-width">
                    <div class="data-label">Nombre del Archivo PDF</div>
                    <div id="doc-pdf-name" class="data-value">-</div>
                </div>
                <div class="data-item">
                    <div class="data-label">Identificador del Documento</div>
                    <div id="doc-id" class="data-value">-</div>
                </div>
                <div class="data-item">
                    <div class="data-label">Tipo de Documento</div>
                    <div id="doc-type" class="data-value">-</div>
                </div>
                <div class="data-item full-width">
                    <div class="data-label">Descripción del Tipo de Documento</div>
                    <div id="doc-type-desc" class="data-value">-</div>
                </div>
                <div class="data-item">
                    <div class="data-label">Fecha y Hora de Firmado</div>
                    <div id="doc-signed-at" class="data-value">-</div>
                </div>
                <div class="data-item">
                    <div class="data-label">Sistema Origen</div>
                    <div id="doc-system" class="data-value">-</div>
                </div>
                <div class="data-item full-width">
                    <div class="data-label">Dependencia Origen</div>
                    <div id="doc-origin-dep" class="data-value">-</div>
                </div>
                <div class="data-item hash-box full-width">
                    <div class="data-label">Huella Digital (SHA-256) - Integridad Criptográfica</div>
                    <div id="doc-hash" class="data-value">-</div>
                </div>
            </div>
            </div>

            <div id="audit-details">
                <div class="section-title">Registro de Firmantes</div>
                <div id="signers-container">
                    <!-- Contenido dinámico -->
                </div>

                <div class="section-title">Constancia de Conservación y Sellado de Tiempo</div>
                <div class="data-grid">
                    <div class="data-item full-width">
                        <div class="data-label">Autoridad Emisora de Sellado de Tiempo (Timestamp)</div>
                        <div id="doc-timestamp" class="data-value">-</div>
                    </div>
                </div>
            </div>

            <button id="download-btn" class="btn-download" onclick="solicitarDescarga()">Descargar Archivo Original</button>
            <div id="readonly-notice" class="notice"></div>
        </div>
    </div>

    <script>
        const POC_UUID = '3fa85f64-5717-4562-b3fc-2c963f66afa6';

        async function fetchDocumentByUUID(uuid) {
            const res = await fetch('/api/audit_document');
            if (!res.ok) {
                throw new Error('No se pudo obtener el estado del documento.');
            }
            const data = await res.json();
            return { status: 200, data: data };
        }

        async function ejecutarCarga() {
            const urlParams = new URLSearchParams(window.location.search);
            const uuid = urlParams.get('uuid') || POC_UUID;

            try {
                const response = await fetchDocumentByUUID(uuid);
                mostrarResultados(response.data);
            } catch (error) {
                mostrarError(error.message);
            } finally {
                document.getElementById('loader').style.display = 'none';
            }
        }

        function mostrarResultados(data) {
            const resultSection = document.getElementById('result-section');
            const metadataSection = document.getElementById('metadata-section');
            const banner = document.getElementById('status-banner');
            const auditDetails = document.getElementById('audit-details');
            const downloadBtn = document.getElementById('download-btn');
            const readonlyNotice = document.getElementById('readonly-notice');
            const signersContainer = document.getElementById('signers-container');

            resultSection.style.display = 'block';
            metadataSection.style.display = 'block';
            signersContainer.innerHTML = ''; 

            const esVigente = data.document_status === 'vigente';

            document.getElementById('doc-id').textContent = data.document_id || '-';
            document.getElementById('doc-pdf-name').textContent = data.pdf_name || '-';
            document.getElementById('doc-type').textContent = data.doc_type || '-';
            document.getElementById('doc-type-desc').textContent = data.doc_type_description || '-';
            document.getElementById('doc-signed-at').textContent = data.signed_at || '-';
            document.getElementById('doc-system').textContent = data.origin_system || '-';
            document.getElementById('doc-origin-dep').textContent = data.origin_dependency || '-';
            document.getElementById('doc-hash').textContent = data.document_hash || '-';

            if (esVigente) {
                banner.className = 'status-banner status-valid';
                banner.textContent = 'ESTADO: DOCUMENTO VÁLIDO E ÍNTEGRO - VIGENTE';
                
                auditDetails.style.display = 'block';
                document.getElementById('doc-timestamp').textContent = data.timestamp_authority || 'No disponible';

                if (data.signers && data.signers.length > 0) {
                    data.signers.forEach(signer => {
                        signersContainer.innerHTML += `
                            <div class="signer-card">
                                <div class="signer-header">
                                    <div class="signer-name">${signer.name}</div>
                                    <div class="signer-status-badge">${signer.status || 'Firma Válida'}</div>
                                </div>
                                <div class="signer-grid">
                                    <div class="signer-field">
                                        <span class="field-label">RFC</span>
                                        <span class="field-value">${signer.rfc || '-'}</span>
                                    </div>
                                    <div class="signer-field">
                                        <span class="field-label">Fecha y Hora de Firma</span>
                                        <span class="field-value">${signer.signed_at || '-'}</span>
                                    </div>
                                    <div class="signer-field">
                                        <span class="field-label">Dependencia</span>
                                        <span class="field-value">${signer.dependency || '-'}</span>
                                    </div>
                                    <div class="signer-field">
                                        <span class="field-label">Cargo</span>
                                        <span class="field-value">${signer.position || '-'}</span>
                                    </div>
                                </div>
                            </div>
                        `;
                    });
                } else {
                    signersContainer.innerHTML = '<div style="color: var(--text-muted); font-size: 0.85rem;">No se encontraron registros de firmantes.</div>';
                }

                if (data.downloadable === true) {
                    downloadBtn.style.display = 'block';
                    readonlyNotice.style.display = 'none';
                } else {
                    downloadBtn.style.display = 'none';
                    readonlyNotice.style.display = 'block';
                    readonlyNotice.className = 'notice notice-warning';
                    readonlyNotice.textContent = 'AVISO: Documento validado legalmente. Políticas de confidencialidad restringen su descarga directa (Modo Solo Lectura).';
                }

            } else {
                banner.className = 'status-banner status-invalid';
                banner.textContent = (data.document_status === 'revocado') ? 'ESTADO: DOCUMENTO REVOCADO O ANULADO' : 'ESTADO: DOCUMENTO EN PROCESO DE FIRMADO (PENDIENTE)';
                
                auditDetails.style.display = 'none'; 
                downloadBtn.style.display = 'none';  
                
                readonlyNotice.style.display = 'block';
                readonlyNotice.className = 'notice notice-danger';
                readonlyNotice.textContent = (data.document_status === 'revocado') 
                    ? 'ACCESO DENEGADO: El documento ha sido revocado. Se muestran únicamente identificadores para propósitos de auditoría y trazabilidad.'
                    : 'AVISO: El documento aún no cuenta con firmas electrónicas aplicadas.';
            }
        }

        function mostrarError(mensaje) {
            document.getElementById('result-section').style.display = 'block';
            document.getElementById('metadata-section').style.display = 'none';
            document.getElementById('audit-details').style.display = 'none';
            document.getElementById('download-btn').style.display = 'none';
            document.getElementById('readonly-notice').style.display = 'none';

            const banner = document.getElementById('status-banner');
            banner.className = 'status-banner status-invalid';
            banner.textContent = `ATENCIÓN: ${mensaje.toUpperCase()}`;
        }

        function solicitarDescarga() {
            alert("Iniciando solicitud de descarga segura del documento original...");
        }

        window.addEventListener('DOMContentLoaded', ejecutarCarga);
    </script>
</body>
</html>
"""


HTML_PAGE = """<!DOCTYPE html>
<html lang="es">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Plataforma Oficial de Multifirmado Digital Avanzado</title>
    <link href="https://fonts.googleapis.com/css2?family=Roboto:wght@300;400;500;700&family=Source+Code+Pro:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {
            --gov-wine: #691C32;
            --gov-wine-dark: #4e1424;
            --gov-gold: #BC955C;
            --gov-gold-light: #fdfbf7;
            --gov-gray-bg: #f4f6f8;
            --gov-border: #d0d7de;
            --gov-text: #1a1f24;
            --gov-text-muted: #57606a;
            --status-green: #198754;
            --status-green-bg: #d1e7dd;
            --status-red: #dc3545;
            --status-red-bg: #f8d7da;
        }

        * { box-sizing: border-box; margin: 0; padding: 0; }

        body {
            font-family: 'Roboto', Arial, sans-serif;
            background-color: var(--gov-gray-bg);
            color: var(--gov-text);
            line-height: 1.4;
        }

        /* Barra Superior */
        .gov-header {
            background-color: var(--gov-wine);
            color: #ffffff;
            padding: 0.85rem 2rem;
            border-bottom: 4px solid var(--gov-gold);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .gov-header h1 {
            font-size: 1.25rem;
            font-weight: 700;
        }

        .gov-header span {
            font-size: 0.8rem;
            opacity: 0.9;
        }

        .main-container {
            max-width: 1380px;
            margin: 1.5rem auto;
            padding: 0 1rem;
            display: grid;
            grid-template-columns: 340px 1fr;
            gap: 1.5rem;
        }

        @media (max-width: 1050px) {
            .main-container { grid-template-columns: 1fr; }
        }

        /* Paneles */
        .panel {
            background: #ffffff;
            border: 1px solid var(--gov-border);
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
            margin-bottom: 1.25rem;
        }

        .panel-header {
            background-color: #ffffff;
            border-bottom: 2px solid var(--gov-gold);
            padding: 0.65rem 1rem;
            font-weight: 700;
            font-size: 0.95rem;
            color: var(--gov-wine);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }

        .panel-body { padding: 1rem; }

        /* Botones */
        .btn-list {
            display: flex;
            flex-direction: column;
            gap: 0.6rem;
        }

        .btn {
            font-family: inherit;
            font-size: 0.88rem;
            font-weight: 500;
            padding: 0.7rem 0.9rem;
            border: 1px solid var(--gov-border);
            border-radius: 4px;
            background: #ffffff;
            cursor: pointer;
            text-align: left;
            display: flex;
            justify-content: space-between;
            align-items: center;
            transition: all 0.15s;
        }

        .btn:hover { background-color: var(--gov-gold-light); border-color: var(--gov-gold); }

        .btn-primary {
            background-color: var(--gov-wine);
            color: #ffffff;
            border-color: var(--gov-wine);
        }
        .btn-primary:hover { background-color: var(--gov-wine-dark); }

        .btn-toggle {
            background-color: #f8fafc;
            border: 1px dashed var(--gov-gold);
            color: var(--gov-wine);
            font-weight: 600;
        }
        .btn-toggle:hover {
            background-color: var(--gov-gold-light);
        }

        .btn-danger {
            color: var(--status-red);
            border-color: var(--status-red);
        }
        .btn-danger:hover {
            background-color: var(--status-red);
            color: #ffffff;
        }

        .btn-reset {
            background-color: #e9ecef;
            color: #495057;
            text-align: center;
            justify-content: center;
        }

        /* Visor de Documento Oficial (Hoja A4 / Oficio) */
        .sheet-container {
            background: #cbd5e1;
            border: 1px solid var(--gov-border);
            border-radius: 4px;
            padding: 2rem 1.5rem;
            display: flex;
            justify-content: center;
        }

        .gov-sheet {
            background: #ffffff;
            width: 100%;
            max-width: 794px; /* Proporción estándar A4 a 96 DPI: 210mm x 297mm */
            min-height: 1123px;
            box-shadow: 0 4px 20px rgba(0,0,0,0.15);
            padding: 3rem 2.8rem 2.2rem 2.8rem;
            border: 1px solid #cbd5e1;
            position: relative;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
        }

        .watermark-alert {
            position: absolute;
            top: 45%;
            left: 50%;
            transform: translate(-50%, -50%) rotate(-25deg);
            font-size: 3.2rem;
            font-weight: 900;
            color: rgba(220, 53, 69, 0.4);
            border: 8px dashed var(--status-red);
            padding: 0.5rem 2rem;
            pointer-events: none;
            display: none;
            z-index: 10;
        }

        .sheet-head {
            border-bottom: 2px solid var(--gov-wine);
            padding-bottom: 0.75rem;
            margin-bottom: 1.25rem;
        }

        .sheet-title {
            font-size: 0.95rem;
            font-weight: 700;
            color: var(--gov-wine);
        }

        .sheet-folio {
            font-size: 0.75rem;
            color: var(--gov-text-muted);
        }

        .sheet-body h2 {
            font-size: 1.05rem;
            font-weight: 700;
            margin-bottom: 0.5rem;
            text-align: center;
        }

        .sheet-body p {
            font-size: 0.85rem;
            margin-bottom: 0.6rem;
            text-align: justify;
            color: #2b2b2b;
        }

        /* ===== BLOQUE EXACTO DE MULTIFIRMA ===== */
        .signature-footer-box {
            padding-top: 1rem;
            margin-top: 2rem;
            background: #ffffff;
        }

        /* Fila Superior: Firmantes con cuadrícula fluida adaptable */
        .signers-row {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(130px, 1fr));
            gap: 0.65rem 0.5rem;
            margin-bottom: 1.25rem;
            align-items: stretch;
        }

        .signer-col {
            font-size: 0.67rem;
            line-height: 1.25;
            display: flex;
            flex-direction: column;
            justify-content: space-between;
            min-height: 125px;
            padding: 0.35rem 0.25rem;
        }

        .signer-info-box {
            display: flex;
            flex-direction: column;
            flex-grow: 1;
        }

        .signer-col-header {
            font-weight: 700;
            color: #000;
            font-size: 0.64rem;
            margin-bottom: 0.15rem;
        }

        .signer-name {
            font-weight: 600;
            color: #111;
            font-size: 0.68rem;
            text-transform: uppercase;
            word-break: break-word;
            min-height: 2.5em; /* Asegura espacio fijo para nombres de 1 o 2 líneas */
            display: flex;
            align-items: flex-start;
            margin-bottom: 0.2rem;
        }

        .signer-meta {
            color: #475569;
            font-size: 0.62rem;
            margin-bottom: 0.1rem;
        }

        .signer-qr-container {
            margin-top: auto;
            padding-top: 0.4rem;
            display: flex;
            align-items: center;
        }

        .signer-qr-thumb {
            width: 44px;
            height: 44px;
            background: #ffffff;
            border: 1px solid #cbd5e1;
            border-radius: 2px;
            padding: 1px;
            image-rendering: pixelated;
        }

        /* Fila Inferior: QR Izquierdo, Cadena Hash y QR Derecho */
        .bottom-signature-bar {
            display: grid;
            grid-template-columns: 95px 1fr 95px;
            gap: 1rem;
            align-items: center;
            padding-top: 0.75rem;
        }

        .main-qr-img {
            width: 95px;
            height: 95px;
            border: 1px solid #cbd5e1;
            border-radius: 3px;
            image-rendering: -webkit-optimize-contrast;
            image-rendering: crisp-edges;
            image-rendering: pixelated;
        }

        .hash-center-box {
            font-size: 0.75rem;
        }

        .hash-title {
            font-weight: 700;
            color: #000;
            margin-bottom: 0.35rem;
            font-size: 0.82rem;
        }

        .hash-text {
            font-family: 'Source Code Pro', monospace;
            font-size: 0.65rem;
            line-height: 1.25;
            color: #222;
            word-break: break-all;
            padding: 0.4rem;
            border-radius: 2px;
        }

        .hash-text.invalid {
            background-color: var(--status-red-bg);
            color: var(--status-red);
            border-color: var(--status-red);
            font-weight: 700;
        }

        /* Status & Logs */
        .status-badge {
            font-size: 0.75rem;
            font-weight: 700;
            padding: 0.2rem 0.5rem;
            border-radius: 3px;
        }
        .badge-ok { background-color: var(--status-green-bg); color: var(--status-green); border: 1px solid var(--status-green); }
        .badge-err { background-color: var(--status-red-bg); color: var(--status-red); border: 1px solid var(--status-red); }

        .console-box {
            font-family: 'Source Code Pro', monospace;
            font-size: 0.78rem;
            background: #ffffff;
            border: 1px solid var(--gov-border);
            padding: 0.65rem;
            max-height: 140px;
            overflow-y: auto;
            color: #222;
        }
    </style>
</head>
<body>

    <div class="gov-header">
        <div>
            <h1>Multifirmado Digital</h1>
        </div>
    </div>

    <div class="main-container">
        
        <!-- Panel Izquierdo: Acciones -->
        <div>
            <div class="panel">
                <div class="panel-header">
                    <span>1. Control de la Cadena de Firmas</span>
                </div>
                <div class="panel-body">
                    <p style="font-size: 0.82rem; color: var(--gov-text-muted); margin-bottom: 0.75rem;">
                        Configura los firmantes del documento y gestiona la cadena de firmas:
                    </p>
                    <div style="margin-bottom: 0.75rem; display: flex; align-items: center; justify-content: space-between; gap: 0.5rem; background: #f8fafc; padding: 0.5rem 0.75rem; border: 1px solid var(--gov-border); border-radius: 4px;">
                        <label for="select-total-signers" style="font-size: 0.82rem; font-weight: 600; color: var(--gov-wine);">Total de Firmantes Requeridos:</label>
                        <select id="select-total-signers" onchange="changeSignersCount(this.value)" style="padding: 0.35rem 0.6rem; font-size: 0.85rem; font-weight: 600; border-radius: 4px; border: 1px solid var(--gov-border); background: #ffffff; color: var(--gov-text); cursor: pointer;">
                            <option value="1">1 Firmante</option>
                            <option value="2">2 Firmantes</option>
                            <option value="3">3 Firmantes</option>
                            <option value="4" selected>4 Firmantes (Estándar)</option>
                            <option value="5">5 Firmantes</option>
                            <option value="6">6 Firmantes</option>
                            <option value="7">7 Firmantes</option>
                            <option value="8">8 Firmantes</option>
                            <option value="9">9 Firmantes</option>
                            <option value="10">10 Firmantes</option>
                        </select>
                    </div>

                    <!-- Radio Buttons: Firmas Visibles vs Ocultas -->
                    <div style="margin-bottom: 0.75rem; background: #f8fafc; padding: 0.5rem 0.75rem; border: 1px solid var(--gov-border); border-radius: 4px;">
                        <div style="font-size: 0.82rem; font-weight: 600; color: var(--gov-wine); margin-bottom: 0.35rem;">Firmas visibles en el documento:</div>
                        <div style="display: flex; gap: 1.25rem; font-size: 0.82rem;">
                            <label style="display: flex; align-items: center; gap: 0.35rem; cursor: pointer; color: var(--gov-text); font-weight: 500;">
                                <input type="radio" name="visible_signatures" id="radio-vis-true" value="true" checked onchange="changeVisibleSignatures(true)">
                                Sí (Mostrar bloques de firmantes)
                            </label>
                            <label style="display: flex; align-items: center; gap: 0.35rem; cursor: pointer; color: var(--gov-text); font-weight: 500;">
                                <input type="radio" name="visible_signatures" id="radio-vis-false" value="false" onchange="changeVisibleSignatures(false)">
                                No (Ocultar)
                            </label>
                        </div>
                    </div>

                    <div class="btn-list">
                        <button class="btn btn-primary" onclick="doAction('/api/sign_next')">
                            <span id="btn-next-text">Añadir Siguiente Firma</span>
                            <span id="badge-count" style="background:rgba(255,255,255,0.2); padding:0.2rem 0.5rem; border-radius:10px; font-size:0.75rem;">0 / 4</span>
                        </button>
                        
                        <!-- BOTÓN DINÁMICO PARA ACTIVAR / DESACTIVAR QRS INDIVIDUALES -->
                        <button class="btn btn-toggle" onclick="doAction('/api/toggle_qrs')">
                            <span id="toggle-qr-text">QRs Individuales: DESACTIVADOS</span>
                        </button>

                        <button class="btn btn-reset" onclick="doAction('/api/reset')">
                            <span>Reiniciar Documento</span>
                        </button>
                    </div>
                </div>
            </div>

            <!-- Diagnóstico de los 4 Firmantes -->
            <div class="panel">
                <div class="panel-header">
                    <span>2. Estado de Cada Sello Criptográfico</span>
                </div>
                <div class="panel-body" id="signers-status-list">
                    <!-- Lista dinámica -->
                </div>
            </div>

            <!-- Registro en Tiempo Real -->
            <div class="panel">
                <div class="panel-header">
                    <span>3. Registro de Eventos</span>
                </div>
                <div class="panel-body">
                    <div class="console-box" id="log-box">
                        > Sistema preparado. Haz clic en 'Añadir Siguiente Firma'...
                    </div>
                </div>
            </div>
        </div>

        <!-- Panel Derecho: Visor del Documento con el Bloque Multifirma -->
        <div>
            <div class="panel">
                <div class="panel-header">
                    <span>Visor del Documento Oficial (Hoja de Dictamen)</span>
                    <span id="file-tag" class="status-badge badge-ok">ACTIVO</span>
                </div>
                <div class="panel-body">
                    <div class="sheet-container">
                        <div class="gov-sheet">
                            <div class="watermark-alert" id="watermark">ALTERADO / FRAUDE</div>

                            <!-- Encabezado de la Hoja -->
                            <div>
                                <div class="sheet-head">
                                    <div class="sheet-title">GOBIERNO CONSTITUCIONAL - DIRECCIÓN GENERAL DE ADMINISTRACIÓN</div>
                                    <div class="sheet-folio">Oficio Núm: DGA/2026/08-0492 | Expediente: 8392-A | Formato: A4 / Oficial | Fecha: 2026.08.26</div>
                                </div>

                                <div class="sheet-body">
                                    <h2>DICTAMEN TÉCNICO Y RESOLUTIVO DE AUTORIZACIÓN</h2>
                                    <p>
                                        Por medio del presente instrumento administrativo, los servidores públicos suscritos en uso de sus facultades legales, emiten <strong>DICTAMEN DE PROCEDENCIA</strong> respecto a la validación de fondos y adjudicación contractual correspondiente al presente ejercicio.
                                    </p>
                                    <p>
                                        Se hace constar que el presente documento adquiere plena validez jurídica mediante la adhesión sucesiva de firmas electrónicas avanzadas conforme a la Ley de Firma Electrónica y el estándar internacional PAdES (ETSI EN 319 142).
                                    </p>
                                </div>
                            </div>

                            <!-- ===== EL BLOQUE EXACTO DE MULTIFIRMA ===== -->
                            <div class="signature-footer-box">
                                
                                <!-- 1. Los 4 Firmantes en Columnas -->
                                <div class="signers-row" id="signers-row">
                                    <!-- Render dinámico de las 4 columnas de firmantes -->
                                </div>

                                <!-- 2. Bloque Inferior con Cadena Hash y QRs -->
                                <div class="bottom-signature-bar">
                                    <div id="left-qr-container">
                                        <img src="" id="main-left-qr" class="main-qr-img">
                                    </div>

                                    <div class="hash-center-box">
                                        <div class="hash-title">Firma electrónica avanzada:</div>
                                        <div class="hash-text" id="hash-text">
                                            Sin firmas registradas.
                                        </div>
                                    </div>

                                    <div id="right-qr-container">
                                        <img src="" id="main-right-qr" class="main-qr-img">
                                    </div>
                                </div>

                            </div>

                        </div>
                    </div>

                    <!-- Resumen físico de bytes -->
                    <div style="margin-top: 0.75rem; font-family:'Source Code Pro', monospace; font-size:0.75rem; color:#475569;" id="file-size-summary">
                        Archivo: oficio_oficial_v0.pdf | Tamaño: 0 Bytes | Revisiones incrementales (%%EOF): 0
                    </div>
                </div>
            </div>
        </div>

    </div>

    <script>
        async function doAction(endpoint, body=null) {
            try {
                const options = { method: 'POST' };
                if (body) {
                    options.headers = { 'Content-Type': 'application/json' };
                    options.body = JSON.stringify(body);
                }
                const res = await fetch(endpoint, options);
                const data = await res.json();
                renderUI(data);
            } catch(e) {
                console.error(e);
            }
        }

        function changeSignersCount(val) {
            doAction('/api/set_signers_count', { count: parseInt(val) });
        }

        function changeVisibleSignatures(val) {
            doAction('/api/set_visible_signatures', { visible: Boolean(val) });
        }

        function renderUI(data) {
            const total = data.total_signers || 4;
            // Sincronizar select
            const selectElem = document.getElementById('select-total-signers');
            if (selectElem && selectElem.value != total) {
                selectElem.value = total;
            }

            // Sincronizar Radio buttons de firmas visibles
            const radioTrue = document.getElementById('radio-vis-true');
            const radioFalse = document.getElementById('radio-vis-false');
            if (data.visible_signatures) {
                radioTrue.checked = true;
            } else {
                radioFalse.checked = true;
            }

            // Actualizar botón de contador
            document.getElementById('badge-count').innerText = `${data.signed_count} / ${total}`;
            const btnNextText = document.getElementById('btn-next-text');
            if (data.signed_count >= total) {
                btnNextText.innerText = 'Proceso de Multifirma Completo';
            } else {
                btnNextText.innerText = `Añadir Firma ${data.signed_count + 1} de ${total}`;
            }

            // Actualizar texto del botón dinámico de toggle QR
            const toggleQrText = document.getElementById('toggle-qr-text');
            if (data.show_individual_qrs) {
                toggleQrText.innerText = 'QRs Individuales: ACTIVADOS';
            } else {
                toggleQrText.innerText = 'QRs Individuales: DESACTIVADOS';
            }

            // Marca de agua
            const watermark = document.getElementById('watermark');
            watermark.style.display = data.is_tampered ? 'block' : 'none';

            // Mostrar u ocultar bloque de firmantes según visible_signatures
            const signersRow = document.getElementById('signers-row');
            if (!data.visible_signatures) {
                signersRow.style.display = 'none';
            } else {
                signersRow.style.display = 'grid';
                // Renderizar únicamente los N firmantes seleccionados
                signersRow.innerHTML = data.signers.map((s, idx) => {
                    if (!s.signed) {
                        return `
                            <div class="signer-col">
                                <div class="signer-info-box">
                                    <div class="signer-col-header">Firmado digitalmente por:</div>
                                </div>
                            </div>
                        `;
                    } else {
                        return `
                            <div class="signer-col active-signed">
                                <div class="signer-info-box">
                                    <div class="signer-col-header">Firmado digitalmente por:</div>
                                    <div class="signer-name">${s.name}</div>
                                    <div class="signer-meta"><strong>Cargo:</strong> ${s.cargo}</div>
                                    <div class="signer-meta"><strong>Fecha:</strong> ${s.fecha}</div>
                                </div>
                                ${(data.show_individual_qrs && s.qr_b64) ? `
                                    <div class="signer-qr-container">
                                        <img src="data:image/png;base64,${s.qr_b64}" class="signer-qr-thumb" alt="QR">
                                    </div>
                                ` : ''}
                            </div>
                        `;
                    }
                }).join('');
            }

            // Renderizar QRs principales y Hash
            const leftQr = document.getElementById('main-left-qr');
            const rightQr = document.getElementById('main-right-qr');
            const hashText = document.getElementById('hash-text');

            if (data.signed_count > 0 && data.left_qr_b64) {
                leftQr.src = `data:image/png;base64,${data.left_qr_b64}`;
                rightQr.src = `data:image/png;base64,${data.right_qr_b64}`;
                leftQr.style.opacity = '1';
                rightQr.style.opacity = '1';

                // Mostrar la cadena de hash concatenada
                const hashes = data.signers.filter(s => s.signed).map(s => s.hash_b64).join('');
                if (data.is_tampered) {
                    hashText.classList.add('invalid');
                    hashText.innerText = "ALERTA: HASH INVALIDADO POR ALTERACIÓN DE BYTES EN EL DOCUMENTO ORIGINAL (FIRMAS CORROMPIDAS).";
                } else {
                    hashText.classList.remove('invalid');
                    hashText.innerText = hashes;
                }
            } else {
                leftQr.style.opacity = '0.1';
                rightQr.style.opacity = '0.1';
                hashText.classList.remove('invalid');
                hashText.innerText = "";
            }

            // Panel de estado criptográfico
            const statusList = document.getElementById('signers-status-list');
            if (data.signed_count === 0) {
                statusList.innerHTML = '<p style="font-size:0.82rem; color:var(--gov-text-muted);">Sin firmas registradas en el archivo.</p>';
            } else {
                statusList.innerHTML = data.signers.filter(s => s.signed).map((s, idx) => {
                    const isOk = !data.is_tampered;
                    return `
                        <div style="margin-bottom:0.6rem; padding-bottom:0.6rem; border-bottom:1px solid #e2e8f0;">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <strong style="font-size:0.8rem;">${idx+1}. ${s.name}</strong>
                                <span class="status-badge ${isOk ? 'badge-ok' : 'badge-err'}">
                                    ${isOk ? 'VÁLIDA' : 'INVALIDADA'}
                                </span>
                            </div>
                            <div style="font-size:0.7rem; color:var(--gov-text-muted);">
                                ${s.cargo} | ${s.fecha}
                            </div>
                        </div>
                    `;
                }).join('');
            }

            // Resumen de archivo
            document.getElementById('file-size-summary').innerText = 
                `Archivo: ${data.filename} | Tamaño: ${data.file_size} Bytes | Revisiones incrementales (%%EOF): ${data.eof_count}`;

            // Logs
            const logBox = document.getElementById('log-box');
            logBox.innerHTML = data.log.map(l => `> ${l}`).join('<br>');
            logBox.scrollTop = logBox.scrollHeight;
        }

        // Cargar estado al inicio
        fetch('/api/status').then(r => r.json()).then(renderUI);
    </script>
</body>
</html>
"""

class ExactLayoutHandler(http.server.SimpleHTTPRequestHandler):
    def end_headers(self):
        # Keep-Alive para reducir sobrecarga TCP/SSL en Render
        self.send_header("Connection", "keep-alive")
        super().end_headers()

    def do_HEAD(self):
        # Render utiliza peticiones HEAD para sus Health Checks
        parsed_path = urllib.parse.urlparse(self.path)
        path_only = parsed_path.path

        if path_only in ["/", "/index.html"]:
            data = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
            self.end_headers()
        elif path_only == "/visor.html":
            data = VISOR_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
            self.end_headers()
        elif path_only in ["/api/status", "/api/audit_document"]:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.end_headers()
        else:
            super().do_HEAD()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        path_only = parsed_path.path

        if path_only in ["/", "/index.html"]:
            data = HTML_PAGE.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            # HTML en caché rápida con revalidación suave (max-age=300, must-revalidate)
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
        elif path_only == "/visor.html":
            data = VISOR_HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "public, max-age=300, must-revalidate")
            self.end_headers()
            self.wfile.write(data)
        elif path_only == "/api/status":
            data = json.dumps(get_current_info()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            # APIs dinámicas no deben ser cacheadas para reflejar estado en tiempo real
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        elif path_only == "/api/audit_document":
            data = json.dumps(get_audit_document_data()).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        else:
            # Archivos estáticos servidos por SimpleHTTPRequestHandler
            super().do_GET()

    def do_POST(self):
        try:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length).decode('utf-8') if content_length > 0 else ""
            payload = json.loads(body) if body else {}

            if self.path == "/api/create_base":
                info = create_base_doc()
            elif self.path == "/api/sign_next":
                if STATE["signed_count"] == 0:
                    create_base_doc()
                info = sign_next()
            elif self.path == "/api/set_signers_count":
                count = payload.get("count", 4)
                info = set_signers_count(count)
            elif self.path == "/api/set_visible_signatures":
                visible = payload.get("visible", True)
                info = set_visible_signatures(visible)
            elif self.path == "/api/toggle_qrs":
                info = toggle_individual_qrs()
            elif self.path == "/api/tamper":
                info = tamper_file()
            elif self.path == "/api/reset":
                info = reset_demo()
            else:
                self.send_response(404)
                self.end_headers()
                return

            data = json.dumps(info).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.send_header("Pragma", "no-cache")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            print(f"Error handling POST {self.path}: {e}")
            err_data = json.dumps({"error": str(e)}).encode("utf-8")
            self.send_response(500)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(err_data)))
            self.send_header("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0")
            self.end_headers()
            self.wfile.write(err_data)

class ThreadingTCPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True

def start_server():
    with ThreadingTCPServer(("", PORT), ExactLayoutHandler) as httpd:
        print(f"Servidor Multifirma Exacto Ejecutándose en http://localhost:{PORT}")
        httpd.serve_forever()

if __name__ == "__main__":
    start_server()
