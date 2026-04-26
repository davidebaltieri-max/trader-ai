#!/usr/bin/env python3
"""
AI Trader — Coinbase CDP (JWT auth) + Claude Haiku
Profili di rischio: BILANCIATO / MEDIO / PERFORMANTE
"""

import os, time, json, logging, sys, statistics, re, secrets
from datetime import datetime, timezone
import requests
import anthropic
import jwt
from cryptography.hazmat.primitives.serialization import load_pem_private_key

# ─────────────────────────────────────────────
# PROFILI DI RISCHIO
# ─────────────────────────────────────────────
RISK_PROFILES = {
    "bilanciato": {
        "pairs":               ["BTC-EUR", "ETH-EUR"],
        "max_trade_eur":       15.0,
        "cash_reserve_eur":    80.0,
        "crash_threshold_pct": 8.0,
        "take_profit_pct":     12.0,
        "stop_loss_pct":       6.0,
        "max_open_positions":  2,
        "ai_style": (
            "Sei MOLTO conservativo. Priorità assoluta: preservare il capitale. "
            "Opera solo con segnali forti e chiari. Prediligi BTC."
        ),
    },
    "medio": {
        "pairs":               ["BTC-EUR", "ETH-EUR", "SOL-EUR"],
        "max_trade_eur":       30.0,
        "cash_reserve_eur":    50.0,
        "crash_threshold_pct": 15.0,
        "take_profit_pct":     20.0,
        "stop_loss_pct":       10.0,
        "max_open_positions":  3,
        "ai_style": (
            "Sei bilanciato. Cerchi equilibrio tra rendimento e rischio. "
            "Operi su segnali ragionevoli di momentum positivo."
        ),
    },
    "performante": {
        "pairs":               ["BTC-EUR", "ETH-EUR", "SOL-EUR", "ADA-EUR"],
        "max_trade_eur":       50.0,
        "cash_reserve_eur":    30.0,
        "crash_threshold_pct": 25.0,
        "take_profit_pct":     35.0,
        "stop_loss_pct":       15.0,
        "max_open_positions":  4,
        "ai_style": (
            "Sei aggressivo e orientato alla performance. Accetti rischi maggiori "
            "per rendimenti più alti. Puoi fare dip-buying su cali moderati."
        ),
    },
}

_profile_name = os.getenv("RISK_PROFILE", "medio").lower().strip()
if _profile_name not in RISK_PROFILES:
    _profile_name = "medio"

PROFILE = RISK_PROFILES[_profile_name]
CONFIG  = {
    **PROFILE,
    "dry_run": os.getenv("DRY_RUN", "true").lower() in ("1", "true", "yes"),
}

# ─────────────────────────────────────────────
# LOGGING
# ─────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
log = logging.getLogger("AITrader")


# ─────────────────────────────────────────────
# COINBASE CLIENT — autenticazione JWT (CDP)
# ─────────────────────────────────────────────
class CoinbaseClient:
    """
    Supporta le nuove CDP API keys di Coinbase (JWT/ES256).
    COINBASE_API_KEY  = nome chiave, es. "organizations/xxx/apiKeys/yyy"
    COINBASE_API_SECRET = chiave privata PEM (con header -----BEGIN EC PRIVATE KEY-----)
    """
    BASE    = "https://api.coinbase.com"
    HOST    = "api.coinbase.com"

    def __init__(self, key_name: str, private_key_pem: str):
        self.key_name = key_name
        # Normalizza la chiave PEM: sostituisce \n letterali con newline reali
        self.private_key_pem = private_key_pem.replace("\\n", "\n")

    def _make_jwt(self, method: str, path: str) -> str:
        """Genera un JWT ES256 valido per 2 minuti."""
        uri     = f"{method.upper()} {self.HOST}{path}"
        now     = int(time.time())
        payload = {
            "sub": self.key_name,
            "iss": "cdp",
            "nbf": now,
            "exp": now + 120,
            "uri": uri,
        }
        headers = {
            "kid":   self.key_name,
            "nonce": secrets.token_hex(10),
            "typ":   "JWT",
        }
        # Carica la chiave EC privata
        key_bytes   = self.private_key_pem.encode()
        private_key = load_pem_private_key(key_bytes, password=None)

        token = jwt.encode(
            payload,
            private_key,
            algorithm="ES256",
            headers=headers,
        )
        return token

    def _get(self, path: str, params: dict = None):
        token = self._make_jwt("GET", path)
        r = requests.get(
            self.BASE + path,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            params=params,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict):
        token = self._make_jwt("POST", path)
        r = requests.post(
            self.BASE + path,
            headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
            json=data,
            timeout=10,
        )
        r.raise_for_status()
        return r.json()

    # ── API methods ──────────────────────────

    def get_accounts(self) -> list:
        return self._get("/api/v3/brokerage/accounts").get("accounts", [])

    def get_balance(self, currency: str) -> float:
        """Ritorna il saldo EUR o EURC (stablecoin euro 1:1)."""
        total = 0.0
        targets = {currency, "EURC"} if currency == "EUR" else {currency}
        for acc in self.get_accounts():
            if acc.get("currency") in targets:
                total += float(acc.get("available_balance", {}).get("value", 0))
        return total

    def get_best_bid_ask(self, product_id: str) -> dict:
        data = self._get("/api/v3/brokerage/best_bid_ask", {"product_ids": product_id})
        for pb in data.get("pricebooks", []):
            bid = float(pb["bids"][0]["price"]) if pb.get("bids") else None
            ask = float(pb["asks"][0]["price"]) if pb.get("asks") else None
            if bid and ask:
                return {"bid": bid, "ask": ask, "mid": (bid + ask) / 2}
        return {}

    def get_candles(self, product_id: str, granularity="ONE_HOUR", limit=25) -> list:
        end   = int(time.time())
        start = end - 3600 * limit
        data  = self._get(
            f"/api/v3/brokerage/products/{product_id}/candles",
            {"start": start, "end": end, "granularity": granularity},
        )
        return data.get("candles", [])

    def get_portfolio(self) -> dict:
        stablecoins = {"EUR", "USD", "USDC", "USDT", "EURC", "DAI", "BUSD"}
        portfolio   = {}
        for acc in self.get_accounts():
            cur = acc.get("currency", "")
            qty = float(acc.get("available_balance", {}).get("value", 0))
            if qty > 1e-8 and cur not in stablecoins:
                portfolio[cur] = qty
        return portfolio

    def market_buy(self, product_id: str, quote_size: float) -> dict:
        if CONFIG["dry_run"]:
            log.info(f"[DRY-RUN] BUY {product_id} €{quote_size:.2f}")
            return {"dry_run": True}
        return self._post("/api/v3/brokerage/orders", {
            "client_order_id": f"ait_{int(time.time())}",
            "product_id":      product_id,
            "side":            "BUY",
            "order_configuration": {
                "market_market_ioc": {"quote_size": str(round(quote_size, 2))}
            },
        })

    def market_sell(self, product_id: str, base_size: float) -> dict:
        if CONFIG["dry_run"]:
            log.info(f"[DRY-RUN] SELL {product_id} qty={base_size:.8f}")
            return {"dry_run": True}
        return self._post("/api/v3/brokerage/orders", {
            "client_order_id": f"ait_{int(time.time())}",
            "product_id":      product_id,
            "side":            "SELL",
            "order_configuration": {
                "market_market_ioc": {"base_size": str(round(base_size, 8))}
            },
        })


# ─────────────────────────────────────────────
# MARKET DATA
# ─────────────────────────────────────────────
def enrich_market(cb: CoinbaseClient) -> dict:
    data = {}
    for pair in CONFIG["pairs"]:
        try:
            prices = cb.get_best_bid_ask(pair)
            if not prices.get("mid"):
                continue
            candles    = cb.get_candles(pair)
            change_24h = volatility = None
            closes     = [float(c["close"]) for c in candles if "close" in c]
            if len(closes) >= 2:
                change_24h = ((closes[0] - closes[-1]) / closes[-1]) * 100
            if len(closes) >= 6:
                changes    = [(closes[i] - closes[i+1]) / closes[i+1] * 100 for i in range(5)]
                volatility = statistics.stdev(changes)
            data[pair] = {**prices, "change_24h": change_24h, "volatility": volatility}
            chg = f"{change_24h:+.2f}%" if change_24h is not None else "n/d"
            log.info(f"{pair}: €{prices['mid']:.4f}  24h={chg}")
        except Exception as e:
            log.warning(f"Errore dati {pair}: {e}")
    return data


# ─────────────────────────────────────────────
# AI ENGINE
# ─────────────────────────────────────────────
def ask_ai(client: anthropic.Anthropic, market_data: dict,
           portfolio: dict, eur_balance: float) -> list:

    usable = max(0.0, eur_balance - CONFIG["cash_reserve_eur"])

    portfolio_lines = "\n".join(
        f"  {sym}: {qty:.8f} unità"
        for sym, qty in portfolio.items()
    ) or "  (nessuna posizione aperta)"

    market_lines = "\n".join(
        f"  {pair}: mid=€{d['mid']:.4f}  "
        f"24h={d['change_24h']:+.2f}%  "
        f"vol={d.get('volatility') or 0:.2f}%"
        for pair, d in market_data.items()
        if d.get("change_24h") is not None
    )

    prompt = f"""Profilo: {_profile_name.upper()} — {CONFIG['ai_style']}

PORTAFOGLIO:
  EUR disponibile: €{eur_balance:.2f} (usabile: €{usable:.2f}, riserva €{CONFIG['cash_reserve_eur']:.0f})
  Posizioni: {len(portfolio)}/{CONFIG['max_open_positions']}

CRYPTO IN PORTAFOGLIO:
{portfolio_lines}

MERCATO (Coinbase live):
{market_lines}

LIMITI:
- Max €{CONFIG['max_trade_eur']:.0f} per trade
- Take profit: +{CONFIG['take_profit_pct']:.0f}% | Stop loss: -{CONFIG['stop_loss_pct']:.0f}%
- Solo coppie: {CONFIG['pairs']}
- Non superare {CONFIG['max_open_positions']} posizioni aperte

Decidi 0-2 operazioni. Rispondi SOLO con JSON array valido:
[{{"action":"buy","pair":"BTC-EUR","amount_eur":20,"reason":"motivazione"}}]
Se non operi: []"""

    msg = client.messages.create(
        model      = "claude-haiku-4-5-20251001",
        max_tokens = 400,
        messages   = [{"role": "user", "content": prompt}],
    )
    raw = msg.content[0].text.strip()
    log.info(f"AI → {raw}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\[[\s\S]*?\]', raw)
        return json.loads(m.group(0)) if m else []


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    mode = "🟡 DRY-RUN" if CONFIG["dry_run"] else "🔴 LIVE"
    log.info("═" * 60)
    log.info(f"AI TRADER [{mode}] — Profilo: {_profile_name.upper()}")
    log.info(f"Coppie: {CONFIG['pairs']}")
    log.info(f"Max trade: €{CONFIG['max_trade_eur']} | Riserva: €{CONFIG['cash_reserve_eur']}")
    log.info(f"Orario: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    # Credenziali
    cb_key    = os.getenv("COINBASE_API_KEY",    "")
    cb_secret = os.getenv("COINBASE_API_SECRET", "")
    ai_key    = os.getenv("ANTHROPIC_API_KEY",   "")

    if not all([cb_key, cb_secret, ai_key]):
        log.error("Credenziali mancanti — controlla i Secrets GitHub")
        sys.exit(1)

    cb     = CoinbaseClient(cb_key, cb_secret)
    claude = anthropic.Anthropic(api_key=ai_key)

    # Test connessione Coinbase + diagnostica conti
    try:
        accounts = cb.get_accounts()
        log.info(f"Coinbase OK - {len(accounts)} conti trovati:")
        for acc in accounts:
            cur   = acc.get("currency", "?")
            avail = float(acc.get("available_balance", {}).get("value", 0))
            total = float((acc.get("balance") or {}).get("value", 0))
            atype = acc.get("type", "?")
            if avail > 0.0001 or total > 0.0001:
                log.info(f"   {cur}: disponibile={avail:.6f}  totale={total:.6f}  tipo={atype}")
        eur_balance = cb.get_balance("EUR")
        log.info(f"Saldo EUR rilevato dal bot: {eur_balance:.2f}")
    except requests.HTTPError as e:
        log.error(f"Coinbase auth fallita: {e.response.status_code} {e.response.text}")
        sys.exit(1)
    except Exception as e:
        log.error(f"Errore connessione: {e}")
        sys.exit(1)

    # Dati mercato
    market_data = enrich_market(cb)
    if not market_data:
        log.warning("Nessun dato di mercato — ciclo saltato")
        sys.exit(0)

    # Crash guard
    for pair, d in market_data.items():
        if d.get("change_24h") is not None and d["change_24h"] < -CONFIG["crash_threshold_pct"]:
            log.warning(f"⚠️  {pair} crollo ({d['change_24h']:.1f}%) — operazioni sospese")
            sys.exit(0)

    # Portafoglio
    portfolio = cb.get_portfolio()
    log.info(f"Posizioni: {list(portfolio.keys()) or 'nessuna'}")

    # AI
    trades = ask_ai(claude, market_data, portfolio, eur_balance)
    log.info(f"AI suggerisce {len(trades)} operazioni")

    # Esecuzione
    for t in trades:
        action     = t.get("action")
        pair       = t.get("pair")
        amount_eur = float(t.get("amount_eur", 0))
        reason     = t.get("reason", "")

        if pair not in CONFIG["pairs"]:
            log.warning(f"Coppia non autorizzata: {pair} — skip"); continue
        if amount_eur > CONFIG["max_trade_eur"]:
            amount_eur = CONFIG["max_trade_eur"]
        usable = eur_balance - CONFIG["cash_reserve_eur"]
        if action == "buy" and amount_eur > usable:
            log.warning(f"Fondi insufficienti (usabili €{usable:.2f}) — skip"); continue
        if action == "buy" and len(portfolio) >= CONFIG["max_open_positions"]:
            log.warning(f"Max posizioni raggiunte — skip"); continue

        log.info(f"▶ {action.upper()} {pair} €{amount_eur:.2f} | {reason}")
        try:
            if action == "buy":
                result = cb.market_buy(pair, amount_eur)
                log.info(f"✓ Acquisto: {json.dumps(result)}")
                eur_balance -= amount_eur
            elif action == "sell":
                base_cur = pair.split("-")[0]
                qty      = portfolio.get(base_cur, 0)
                price    = market_data[pair]["mid"]
                sell_qty = min(qty, amount_eur / price)
                if sell_qty < 1e-8:
                    log.warning(f"Quantità insufficiente per {pair}"); continue
                result = cb.market_sell(pair, sell_qty)
                log.info(f"✓ Vendita: {json.dumps(result)}")
        except requests.HTTPError as e:
            log.error(f"✗ Errore API: {e.response.status_code} — {e.response.text}")
        except Exception as e:
            log.error(f"✗ Errore: {e}")

    log.info("Ciclo completato ✓")


if __name__ == "__main__":
    main()
