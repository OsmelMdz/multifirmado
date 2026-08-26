# Plataforma de Multifirmado Digital de Oficios

Prueba de Concepto (PoC) de firmado electrónico avanzado incremental con estándar PAdES (ETSI EN 319 142).

## Características
- Firma criptográfica secuencial basada en certificados X.509.
- Estructura incremental pura (`IncrementalPdfFileWriter`).
- Selector dinámico de 1 a 10 firmantes.
- Soporte para conmutar QRs individuales y firmas visibles/invisibles.
- Validación de integridad con detección de alteraciones de bytes (tampering).

## Ejecución Local
```bash
pip install -r requirements.txt
python server.py
```
Abre [http://localhost:8000](http://localhost:8000) en tu navegador.
