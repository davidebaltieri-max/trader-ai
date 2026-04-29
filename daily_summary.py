#!/usr/bin/env python3
"""
Invia una mail giornaliera con il riepilogo delle operazioni del bot.
Viene eseguito dal workflow daily_summary.yml ogni sera alle 21:00 (ora italiana).
Usa Gmail con App Password (non la password normale dell'account).
"""

import os, json, glob, smtplib, sys
from datetime import datetime, timezone, timedelta
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
GMAIL_USER    = os.getenv("GMAIL_USER", "")
GMAIL_PASS    = os.getenv("GMAIL_APP_PASSWORD", "")
NOTIFY_EMAIL  = os.getenv("NOTIFY_EMAIL", GMAIL_USER)
DRY_RUN       = os.getenv("DRY_RUN", "true").lower() in ("1", "true", "yes")


def load_today_trades() -> list:
    """Carica le operazioni del giorno corrente dal file JSON."""
    today    = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    log_file = f"trades_{today}.json"
    if not os.path.exists(log_file):
        # Prova anche ieri (per fusi orari)
        yesterday = (datetime.now(timezone.utc) - timedelta(days=1)).strftime("%Y-%m-%d")
        log_file  = f"trades_{yesterday}.json"
    if not os.path.exists(log_file):
        return []
    with open(log_file) as f:
        return json.load(f)


def build_html(trades: list, date_str: str) -> str:
    mode_badge = (
        '<span style="background:#f59e0b;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">DRY-RUN</span>'
        if DRY_RUN else
        '<span style="background:#ef4444;color:#fff;padding:2px 8px;border-radius:4px;font-size:12px;">LIVE</span>'
    )

    if not trades:
        body = """
        <div style="text-align:center;padding:40px;color:#6b7280;">
            <div style="font-size:48px;">😴</div>
            <div style="font-size:16px;margin-top:12px;">Nessuna operazione eseguita oggi.</div>
            <div style="font-size:13px;color:#9ca3af;margin-top:8px;">
                Il bot ha analizzato il mercato ma non ha trovato opportunità con segnali sufficientemente chiari.
            </div>
        </div>"""
    else:
        buys  = [t for t in trades if t["action"] == "buy"]
        sells = [t for t in trades if t["action"] == "sell"]
        tot_bought = sum(t["amount_eur"] for t in buys)
        tot_sold   = sum(t["amount_eur"] for t in sells)
        net        = tot_sold - tot_bought

        rows = ""
        for t in trades:
            ts      = t["ts"][:16].replace("T", " ")
            color   = "#16a34a" if t["action"] == "buy" else "#dc2626"
            badge   = f'<span style="background:{color};color:#fff;padding:1px 8px;border-radius:4px;font-size:11px;font-weight:700;">{t["action"].upper()}</span>'
            amount  = f'{"−" if t["action"] == "buy" else "+"} €{t["amount_eur"]:.2f}'
            amt_col = f'<span style="color:{color};font-weight:700;">{amount}</span>'
            rows += f"""
            <tr style="border-bottom:1px solid #f3f4f6;">
                <td style="padding:10px 8px;font-size:12px;color:#6b7280;">{ts}</td>
                <td style="padding:10px 8px;">{badge}</td>
                <td style="padding:10px 8px;font-weight:700;">{t["pair"]}</td>
                <td style="padding:10px 8px;font-size:12px;font-family:monospace;">€{t["price"]:.4f}</td>
                <td style="padding:10px 8px;font-family:monospace;">{amt_col}</td>
                <td style="padding:10px 8px;font-size:11px;color:#6b7280;max-width:200px;">{t.get("reason","")}</td>
            </tr>"""

        net_color = "#16a34a" if net >= 0 else "#dc2626"
        net_sign  = "+" if net >= 0 else ""

        body = f"""
        <div style="display:flex;gap:16px;margin-bottom:20px;flex-wrap:wrap;">
            <div style="flex:1;min-width:120px;background:#f0fdf4;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:22px;font-weight:700;color:#16a34a;">{len(buys)}</div>
                <div style="font-size:12px;color:#6b7280;">Acquisti</div>
                <div style="font-size:13px;font-weight:600;color:#16a34a;">−€{tot_bought:.2f}</div>
            </div>
            <div style="flex:1;min-width:120px;background:#fef2f2;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:22px;font-weight:700;color:#dc2626;">{len(sells)}</div>
                <div style="font-size:12px;color:#6b7280;">Vendite</div>
                <div style="font-size:13px;font-weight:600;color:#dc2626;">+€{tot_sold:.2f}</div>
            </div>
            <div style="flex:1;min-width:120px;background:#f8fafc;border-radius:8px;padding:16px;text-align:center;">
                <div style="font-size:22px;font-weight:700;color:{net_color};">{net_sign}€{net:.2f}</div>
                <div style="font-size:12px;color:#6b7280;">Flusso netto</div>
                <div style="font-size:13px;color:#9ca3af;">{len(trades)} operazioni totali</div>
            </div>
        </div>

        <table style="width:100%;border-collapse:collapse;font-size:13px;">
            <thead>
                <tr style="background:#f8fafc;">
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Ora</th>
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Azione</th>
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Asset</th>
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Prezzo</th>
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Importo</th>
                    <th style="padding:8px;text-align:left;color:#6b7280;font-size:11px;text-transform:uppercase;">Motivazione AI</th>
                </tr>
            </thead>
            <tbody>{rows}</tbody>
        </table>"""

    return f"""
<!DOCTYPE html>
<html>
<body style="margin:0;padding:0;background:#f1f5f9;font-family:'Segoe UI',Arial,sans-serif;">
<div style="max-width:700px;margin:30px auto;background:#fff;border-radius:12px;overflow:hidden;box-shadow:0 2px 8px rgba(0,0,0,0.08);">

    <!-- Header -->
    <div style="background:linear-gradient(135deg,#1e293b,#334155);padding:24px 28px;color:#fff;">
        <div style="display:flex;justify-content:space-between;align-items:center;">
            <div>
                <div style="font-size:20px;font-weight:700;">🤖 AI Trader — Riepilogo Giornaliero</div>
                <div style="font-size:13px;color:#94a3b8;margin-top:4px;">{date_str}</div>
            </div>
            <div>{mode_badge}</div>
        </div>
    </div>

    <!-- Body -->
    <div style="padding:24px 28px;">
        {body}
    </div>

    <!-- Footer -->
    <div style="background:#f8fafc;padding:16px 28px;border-top:1px solid #e2e8f0;font-size:11px;color:#9ca3af;text-align:center;">
        AI Trader · Coinbase · Report automatico generato alle {datetime.now(timezone(timedelta(hours=2))).strftime("%H:%M")} ora italiana
        <br>Le performance passate non garantiscono risultati futuri. Investi solo ciò che puoi permetterti di perdere.
    </div>
</div>
</body>
</html>"""


def send_email(subject: str, html_body: str):
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"]    = GMAIL_USER
    msg["To"]      = NOTIFY_EMAIL
    msg.attach(MIMEText(html_body, "html"))

    with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
        server.login(GMAIL_USER, GMAIL_PASS)
        server.sendmail(GMAIL_USER, NOTIFY_EMAIL, msg.as_string())


def main():
    if not GMAIL_USER or not GMAIL_PASS:
        print("❌ GMAIL_USER o GMAIL_APP_PASSWORD non configurati nei Secrets GitHub")
        sys.exit(1)

    trades   = load_today_trades()
    today    = datetime.now().strftime("%d/%m/%Y")
    n        = len(trades)
    subject  = f"🤖 AI Trader — {today} — {n} operazion{'e' if n==1 else 'i'} eseguit{'a' if n==1 else 'e'}"
    html     = build_html(trades, today)

    try:
        send_email(subject, html)
        print(f"✓ Email inviata a {NOTIFY_EMAIL} ({n} operazioni)")
    except Exception as e:
        print(f"✗ Errore invio email: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
