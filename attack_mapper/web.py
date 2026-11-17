"""Local web interface for testing the ATT&CK mapper."""

import argparse
import html
import json
from email import policy
from email.parser import BytesParser
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs

from .mapper import AttackMapper

MAX_REPORT_BYTES = 1_000_000


def render_page(report: str = "", result: dict[str, object] | None = None) -> str:
    """Render the report input form and, when available, analysis results."""
    result_html = ""
    if result is not None:
        result_json = html.escape(json.dumps(result, ensure_ascii=False, indent=2))
        rows: list[str] = []
        for event in result["events"]:  # type: ignore[union-attr]
            for technique in event["techniques"]:
                rows.append(
                    "<tr>"
                    f"<td>{html.escape(technique['technique_id'])}</td>"
                    f"<td>{html.escape(technique['technique_name'])}</td>"
                    f"<td>{html.escape(technique['tactic'])}</td>"
                    f"<td>{technique['confidence']:.2f}</td>"
                    f"<td>L{technique['source_line']}: "
                    f"{html.escape(technique['evidence'])}</td>"
                    "</tr>"
                )
        result_html = f"""
        <section>
          <h2>Résultats ({result['event_count']} événements)</h2>
          <table>
            <thead><tr><th>ID</th><th>Technique</th><th>Tactique</th>
              <th>Confiance</th><th>Preuve</th></tr></thead>
            <tbody>{''.join(rows)}</tbody>
          </table>
          <details><summary>JSON</summary><pre>{result_json}</pre></details>
        </section>
        """

    return f"""<!doctype html>
<html lang="fr"><head><meta charset="utf-8">
<title>VulnLab ATT&amp;CK Mapper</title>
<style>
body {{ font: 16px system-ui, sans-serif; max-width: 1100px; margin: 2rem auto; padding: 0 1rem; }}
textarea {{ width: 100%; min-height: 18rem; font: 14px monospace; }}
button {{ padding: .6rem 1rem; cursor: pointer; }}
table {{ border-collapse: collapse; width: 100%; margin-top: 1rem; }}
th, td {{ border: 1px solid #ccc; padding: .5rem; text-align: left; vertical-align: top; }}
th {{ background: #f2f2f2; }} pre {{ overflow: auto; background: #f6f6f6; padding: 1rem; }}
</style></head>
<body>
<h1>VulnLab ATT&amp;CK Mapper</h1>
<p>Interface locale de test. Chaque recommandation conserve sa preuve et sa ligne source.</p>
<form method="post" enctype="multipart/form-data">
  <label for="report">Rapport Red Team</label>
  <textarea id="report" name="report" placeholder="Collez un rapport texte ou Markdown...">{html.escape(report)}</textarea>
  <p><label>Ou importer un fichier texte/Markdown :
    <input type="file" name="report_file" accept=".txt,.md,.markdown">
  </label></p>
  <button type="submit">Analyser le rapport</button>
</form>
{result_html}
</body></html>"""


def _extract_report(content_type: str, body: bytes) -> str:
    if len(body) > MAX_REPORT_BYTES:
        raise ValueError("Le rapport dépasse la limite de 1 Mo.")
    if content_type.startswith("multipart/form-data"):
        message = BytesParser(policy=policy.default).parsebytes(
            b"Content-Type: " + content_type.encode("utf-8") + b"\r\n\r\n" + body
        )
        payload = message.get_payload()
        parts = payload if isinstance(payload, list) else []
        for part in parts:
            if part.get_content_disposition() == "form-data":
                name = part.get_param("name", header="content-disposition")
                if name in {"report", "report_file"}:
                    value = part.get_content()
                    if value:
                        return value if isinstance(value, str) else value.decode("utf-8")
        return ""
    fields = parse_qs(body.decode("utf-8"), keep_blank_values=True)
    return fields.get("report", [""])[0]


class MapperHandler(BaseHTTPRequestHandler):
    """Handle the local mapper form without persisting report contents."""

    mapper = AttackMapper()

    def do_GET(self) -> None:
        self._send_html(render_page())

    def do_POST(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            report = _extract_report(self.headers.get("Content-Type", ""), self.rfile.read(length))
            result = self.mapper.analyze(report)
            self._send_html(render_page(report, result))
        except (ValueError, UnicodeDecodeError) as exc:
            self.send_error(HTTPStatus.BAD_REQUEST, str(exc))

    def _send_html(self, page: str) -> None:
        encoded = page.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format: str, *args: object) -> None:
        return


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Run the local ATT&CK mapper UI.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8000)
    args = parser.parse_args(argv)
    server = ThreadingHTTPServer((args.host, args.port), MapperHandler)
    print(f"Interface disponible sur http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        return 0
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
