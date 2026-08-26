"""
PoC: Demostración Completa y Detallada del Multifirmado Digital Incremental (PAdES)
1. Crea un documento PDF base (Contrato original).
2. Aplica la Firma 1 (Alice) -> Genera v1.pdf
3. Aplica la Firma 2 Incremental (Bob) -> Genera v2.pdf (Multifirmado)
4. Muestra la estructura interna física (/ByteRange, xref, %%EOF)
5. Simula un ataque (modificación fraudulenta de v1 y v2) y demuestra la ruptura criptográfica.
"""

import os
import sys
import hashlib
from pathlib import Path

# ReportLab para generar el PDF inicial
from reportlab.lib.pagesizes import letter
from reportlab.pdfgen import canvas

# pyHanko para firmas PAdES y validación
from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
from pyhanko.pdf_utils.reader import PdfFileReader
from pyhanko.sign import fields, signers
from pyhanko.sign.validation import validate_pdf_signature, ValidationContext
from pyhanko_certvalidator import ValidationContext as TrustContext
from pyhanko_certvalidator.registry import SimpleCertificateStore
from asn1crypto import x509 as asn1_x509, pem as asn1_pem

WORKSPACE = Path(__file__).parent
OUTPUT_DIR = WORKSPACE / "output"
CERTS_DIR = WORKSPACE / "certs"
OUTPUT_DIR.mkdir(exist_ok=True)


def create_base_pdf(filepath: Path):
    """Crea un documento PDF inicial simple."""
    c = canvas.Canvas(str(filepath), pagesize=letter)
    c.setFont("Helvetica-Bold", 16)
    c.drawString(100, 720, "CONTRATO DE ACUERDO MUTUO")
    c.setFont("Helvetica", 11)
    c.drawString(100, 680, "Este documento requiere la firma digital de dos partes:")
    c.drawString(120, 660, "1. Alice Valenzuela (Directora Operativa)")
    c.drawString(120, 640, "2. Bob Martinez (Representante Legal)")
    c.drawString(100, 600, "Clausula 1: Ambas partes aceptan los terminos y condiciones tecnicas.")
    c.drawString(100, 580, "Cualquier modificacion no autorizada invalidara la cadena criptografica.")
    
    # Dibujar cajas para las firmas
    c.rect(100, 450, 180, 70)
    c.drawString(110, 505, "Firma Alice (Firmante 1)")
    
    c.rect(320, 450, 180, 70)
    c.drawString(330, 505, "Firma Bob (Firmante 2)")
    
    c.save()
    print(f"[1] Documento Base Creado: {filepath.name} ({os.path.getsize(filepath)} bytes)")


def sign_first_party(input_pdf: Path, output_pdf: Path):
    """Aplica la primera firma (Alice)."""
    signer = signers.SimpleSigner.load(
        key_file=str(CERTS_DIR / "alice_key.pem"),
        cert_file=str(CERTS_DIR / "alice_cert.pem"),
    )

    with open(input_pdf, "rb") as inf:
        w = IncrementalPdfFileWriter(inf)
        # Añadir campo de firma visual
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name="Firma_Alice",
                box=(100, 450, 280, 520)
            )
        )
        meta = signers.PdfSignatureMetadata(
            field_name="Firma_Alice",
            reason="Aprobacion del Contrato",
            location="Madrid, ES"
        )
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer
        )
        with open(output_pdf, "wb") as outf:
            pdf_signer.sign_pdf(w, output=outf)

    print(f"[2] Primera Firma Aplicada (Alice): {output_pdf.name} ({os.path.getsize(output_pdf)} bytes)")


def sign_second_party_incremental(input_pdf: Path, output_pdf: Path):
    """Aplica la segunda firma (Bob) de forma 100% incremental (PAdES append-only)."""
    signer = signers.SimpleSigner.load(
        key_file=str(CERTS_DIR / "bob_key.pem"),
        cert_file=str(CERTS_DIR / "bob_cert.pem"),
    )

    with open(input_pdf, "rb") as inf:
        # Nota clave: IncrementalPdfFileWriter preserva todo el historial de revisiones intacto
        w = IncrementalPdfFileWriter(inf)
        fields.append_signature_field(
            w,
            sig_field_spec=fields.SigFieldSpec(
                sig_field_name="Firma_Bob",
                box=(320, 450, 500, 520)
            )
        )
        meta = signers.PdfSignatureMetadata(
            field_name="Firma_Bob",
            reason="Conformidad Legal Mutua",
            location="Barcelona, ES"
        )
        pdf_signer = signers.PdfSigner(
            meta,
            signer=signer
        )
        with open(output_pdf, "wb") as outf:
            pdf_signer.sign_pdf(w, output=outf)

    print(f"[3] Segunda Firma Aplicada (Bob): {output_pdf.name} ({os.path.getsize(output_pdf)} bytes)")


def inspect_byte_ranges(pdf_path: Path):
    """Inspecciona los rangos de bytes (/ByteRange) y las revisiones incrementales."""
    print(f"\n=======================================================")
    print(f" RADIOGRAFIA DE ESTRUCTURA Y /ByteRange: {pdf_path.name}")
    print(f" Tamano total del archivo: {os.path.getsize(pdf_path)} bytes")
    print(f"=======================================================")
    
    with open(pdf_path, "rb") as f:
        data = f.read()
        reader = PdfFileReader(f)
        
        # Contar cuantas marcas de fin de revision (%%EOF) existen
        eof_count = data.count(b"%%EOF")
        print(f" * Numero de revisiones incrementales (%%EOF encontrados): {eof_count}")
        
        # Extraer campos de firma
        for sig_obj in reader.embedded_signatures:
            name = sig_obj.field_name
            sig_dict = sig_obj.sig_object
            br = [int(x) for x in sig_obj.byte_range]
            
            print(f"\n -> Campo de Firma: '{name}'")
            print(f"    - SubFiltro / Tipo: {sig_dict.get('/SubFilter', 'N/A')}")
            print(f"    - /ByteRange Array: {br}")
            print(f"      * Segmento 1: bytes {br[0]} a {br[0] + br[1]} (Longitud: {br[1]} B)")
            print(f"      * [HUECO /Contents de la firma: bytes {br[0] + br[1]} a {br[2]} -> {br[2] - (br[0] + br[1])} B]")
            print(f"      * Segmento 2: bytes {br[2]} a {br[2] + br[3]} (Longitud: {br[3]} B)")
            print(f"      * Cobertura Total de la Firma: {br[1] + br[3]} bytes protegidos")
            
            # Verificación del hash de los bytes cubiertos
            covered_bytes = data[br[0]:br[0]+br[1]] + data[br[2]:br[2]+br[3]]
            calc_sha256 = hashlib.sha256(covered_bytes).hexdigest()
            print(f"      * SHA-256 de los bytes cubiertos: {calc_sha256}")


def validate_all_signatures(pdf_path: Path):
    """Valida criptograficamente todas las firmas en el archivo."""
    print(f"\n=======================================================")
    print(f" VALIDACION CRIPTOGRAFICA OFICIAL: {pdf_path.name}")
    print(f"=======================================================")

    with open(CERTS_DIR / "ca_cert.pem", "rb") as f:
        _, _, der_bytes = asn1_pem.unarmor(f.read())
        ca_cert = asn1_x509.Certificate.load(der_bytes)
    
    val_ctx = ValidationContext(
        trust_roots=[ca_cert],
        allow_fetching=False
    )

    with open(pdf_path, "rb") as f:
        reader = PdfFileReader(f)
        for sig_obj in reader.embedded_signatures:
            sig_name = sig_obj.field_name
            status = validate_pdf_signature(
                sig_obj,
                signer_validation_context=val_ctx
            )
            print(f"\n [Firma '{sig_name}']")
            print(f"  - Integridad Intacta (Hash valido): {status.intact}")
            print(f"  - Valida criptograficamente: {status.valid}")
            print(f"  - Modificaciones posteriores toleradas: {status.modification_level}")
            print(f"  - Resumen de diagnostico: {status.summary()}")


def simulate_tampering_attack():
    """Simula qué ocurre si un atacante modifica el PDF de v2 (por ejemplo, alterando el texto original)."""
    print(f"\n=======================================================")
    print(f" DEMOSTRACION DE ATAQUE Y DETECCION DE FRAUDE")
    print(f"=======================================================")
    
    v2_path = OUTPUT_DIR / "contrato_multifirmado_v2.pdf"
    tampered_path = OUTPUT_DIR / "contrato_hackeado.pdf"
    
    with open(v2_path, "rb") as f:
        content = bytearray(f.read())
    
    # Alterar 4 bytes en el contenido del stream original (offset 1000)
    idx = content.find(b"stream\r\n")
    if idx == -1:
        idx = content.find(b"stream\n")
    
    if idx != -1:
        target_idx = idx + 10
        # Invertimos los bits de algunos bytes para simular una alteración fraudulenta
        content[target_idx] = content[target_idx] ^ 0xFF
        content[target_idx+1] = content[target_idx+1] ^ 0xFF
        with open(tampered_path, "wb") as f:
            f.write(content)
        print(f" [!] Se genero archivo adulterado: {tampered_path.name}")
        print(f"     Se alteraron bytes en el stream de contenido de la Revision 0 (Offset {target_idx}).")
        
        # Validar el archivo hackeado
        with open(CERTS_DIR / "ca_cert.pem", "rb") as cf:
            _, _, der_bytes = asn1_pem.unarmor(cf.read())
            ca_cert = asn1_x509.Certificate.load(der_bytes)
        val_ctx = ValidationContext(trust_roots=[ca_cert], allow_fetching=False)

        with open(tampered_path, "rb") as f:
            reader = PdfFileReader(f)
            for sig_obj in reader.embedded_signatures:
                sig_name = sig_obj.field_name
                try:
                    status = validate_pdf_signature(
                        sig_obj,
                        signer_validation_context=val_ctx
                    )
                    print(f"\n [Resultado para '{sig_name}' tras el ataque]")
                    print(f"  - Integridad Intacta: {status.intact}  <--- ATENCION: RUPTURA DETECTADA")
                    print(f"  - Valida: {status.valid}")
                    print(f"  - Resumen: {status.summary()}")
                except Exception as e:
                    print(f"\n [Error al procesar '{sig_name}' tras el ataque]: {e}")


if __name__ == "__main__":
    base_pdf = OUTPUT_DIR / "contrato_base_v0.pdf"
    v1_pdf = OUTPUT_DIR / "contrato_firmado_alice_v1.pdf"
    v2_pdf = OUTPUT_DIR / "contrato_multifirmado_v2.pdf"

    print(">>> INICIANDO PRUEBA DE CONCEPTO: MULTIFIRMADO DIGITAL INCREMENTAL <<<\n")
    
    # Paso 1: Crear Documento Original
    create_base_pdf(base_pdf)
    
    # Paso 2: Firma 1 (Alice)
    sign_first_party(base_pdf, v1_pdf)
    
    # Paso 3: Firma 2 (Bob) - Incremental
    sign_second_party_incremental(v1_pdf, v2_pdf)
    
    # Paso 4: Radiografía de Bytes
    inspect_byte_ranges(v2_pdf)
    
    # Paso 5: Validación Criptográfica Formal
    validate_all_signatures(v2_pdf)
    
    # Paso 6: Demostración de Seguridad ante Alteraciones
    simulate_tampering_attack()
