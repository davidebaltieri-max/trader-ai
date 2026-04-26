#!/usr/bin/env python3
"""
AI Trader — Coinbase + Claude AI
Versione con profili di rischio: BILANCIATO / MEDIO / PERFORMANTE
"""

import os, time, json, hmac, hashlib, logging, sys, statistics, re
from datetime import datetime, timezone
import requests
import anthropic

# ─────────────────────────────────────────────
# PROFILI DI RISCHIO
# Imposta RISK_PROFILE nel Secret GitHub oppure
# come variabile d'ambiente locale.
# Valori validi: "bilanciato" | "medio" | "performante"
# ─────────────────────────────────────────────
RISK_PROFILES = {

    "bilanciato": {
        # Coppie: solo le più stabili e liquide
        "pairs":                ["BTC-EUR", "ETH-EUR"],
        "max_trade_eur":        15.0,      # Max per singolo ordine
        "cash_reserve_eur":     80.0,      # Riserva intoccabile
        "crash_threshold_pct":  8.0,       # Pausa se asset cala >8% in 24h
        "min_momentum_pct":     1.5,       # Compra solo se 24h > +1.5%
        "take_profit_pct":      12.0,      # Vendi se P&L > +12%
        "stop_loss_pct":        6.0,       # Vendi se P&L < -6%
        "max_open_positions":   2,
        "ai_style": (
            "Sei MOLTO conservativo. Preferisci non operare se non c'è un segnale "
            "forte e chiaro. Priorità assoluta: preservare il capitale. "
            "Evita acquisti se il mercato è incerto o laterale. "
            "Prediligi BTC per la sua stabilità relativa."
        ),
    },

    "medio": {
        "pairs":                ["BTC-EUR", "ETH-EUR", "SOL-EUR"],
        "max_trade_eur":        30.0,
        "cash_reserve_eur":     50.0,
        "crash_threshold_pct":  15.0,
        "min_momentum_pct":     0.5,
        "take_profit_pct":      20.0,
        "stop_loss_pct":        10.0,
        "max_open_positions":   3,
        "ai_style": (
            "Sei un trader bilanciato. Cerchi un equilibrio tra rendimento e rischio. "
            "Operi quando ci sono segnali ragionevoli di momentum positivo. "
            "Diversifichi tra BTC, ETH e SOL. Prendi profitto con regolarità."
        ),
    },

    "performante": {
        "pairs":                ["BTC-EUR", "ETH-EUR", "SOL-EUR", "ADA-EUR", "MATIC-EUR"],
        "max_trade_eur":        50.0,
        "cash_reserve_eur":     30.0,
        "crash_threshold_pct":  25.0,
        "min_momentum_pct":    -1.0,       # Compra anche in leggero calo (dip buying)
        "take_profit_pct":      35.0,      # Lascia correre i profitti
        "stop_loss_pct":        15.0,      # Tollera drawdown maggiori
        "max_open_positions":   4,
        "ai_style": (
            "Sei aggressivo e orientato alla performance. Cerchi opportunità di rendimento "
            "elevato accettando rischi maggiori. Puoi fare dip-buying su cali moderati. "
            "Diversifichi su più asset incluse altcoin. Lasci correre le posizioni in guadagno "
            "e tagli le perdite solo quando necessario. Priorità: massimizzare i ritorni."
        ),
    },
}

# ─────────────────────────────────────────────
# CARICAMENTO CONFIGURAZIONE
# ─────────────────────────────────────────────
_profile_name = os.getenv("RISK_PROFILE", "medio").lower().strip()
if _profile_name not in RISK_PROFILES:
    print(f"⚠️  RISK_PROFILE '{_profile_name}' non valido. Uso 'medio'.")
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
# COINBASE CLIENT
# ─────────────────────────────────────────────
class CoinbaseClient:
    BASE = "https://api.coinbase.com"

    def __init__(self, api_key: str, api_secret: str):
        self.key    = api_key
        self.secret = api_secret

    def _sign(self, method: str, path: str, body: str = "") -> dict:
        ts  = str(int(time.time()))
        msg = ts + method.upper() + path + body
        sig = hmac.new(self.secret.encode(), msg.encode(), hashlib.sha256).hexdigest()
        return {
            "CB-ACCESS-KEY":       self.key,
            "CB-ACCESS-SIGN":      sig,
            "CB-ACCESS-TIMESTAMP": ts,
            "Content-Type":        "application/json",
        }

    def _get(self, path: str, params: dict = None):
        headers = self._sign("GET", path)
        r = requests.get(self.BASE + path, headers=headers, params=params, timeout=10)
        r.raise_for_status()
        return r.json()

    def _post(self, path: str, data: dict):
        body    = json.dumps(data)
        headers = self._sign("POST", path, body)
        r = requests.post(self.BASE + path, headers=headers, data=body, timeout=10)
        r.raise_for_status()
        return r.json()

    def get_accounts(self) -> list:
        return self._get("/api/v3/brokerage/accounts").get("accounts", [])

    def get_balance(self, currency: str) -> float:
        for acc in self.get_accounts():
            if acc.get("currency") == currency:
                return float(acc.get("available_balance", {}).get("value", 0))
        return 0.0

    def get_best_bid_ask(self, product_id: str) -> dict:
        data = self._get("/api/v3/brokerage/best_bid_ask", {"product_ids": product_id})
        for pb in data.get("pricebooks", []):
            bid = float(pb["bids"][0]["price"]) if pb.get("bids") else None
            ask = float(pb["asks"][0]["price"]) if pb.get("asks") else None
            return {"bid": bid, "ask": ask, "mid": (bid + ask) / 2 if bid and ask else None}
        return {}

    def get_candles(self, product_id: str, granularity="ONE_HOUR", limit=25) -> list:
        end   = int(time.time())
        start = end - 3600 * limit
        data  = self._get(
            f"/api/v3/brokerage/products/{product_id}/candles",
            {"start": start, "end": end, "granularity": granularity}
        )
        return data.get("candles", [])

    def get_portfolio(self) -> dict:
        portfolio = {}
        for acc in self.get_accounts():
            qty = float(acc.get("available_balance", {}).get("value", 0))
            if qty > 1e-8 and acc["currency"] not in ("EUR", "USD", "USDC", "USDT"):
                portfolio[acc["currency"]] = qty
        return portfolio

    def market_buy(self, product_id: str, quote_size: float) -> dict:
        if CONFIG["dry_run"]:
            log.info(f"[DRY-RUN] BUY {product_id} €{quote_size:.2f}")
            return {"dry_run": True, "status": "ok"}
        return self._post("/api/v3/brokerage/orders", {
            "client_order_id": f"ait_{int(time.time())}",
            "product_id":      product_id,
            "side":            "BUY",
            "order_configuration": {
                "market_market_ioc": {"quote_size": str(round(quote_size, 2))}
            }
        })

    def market_sell(self, product_id: str, base_size: float) -> dict:
        if CONFIG["dry_run"]:
            log.info(f"[DRY-RUN] SELL {product_id} qty={base_size:.8f}")
            return {"dry_run": True, "status": "ok"}
        return self._post("/api/v3/brokerage/orders", {
            "client_order_id": f"ait_{int(time.time())}",
            "product_id":      product_id,
            "side":            "SELL",
            "order_configuration": {
                "market_market_ioc": {"base_size": str(round(base_size, 8))}
            }
        })


# ─────────────────────────────────────────────
# MARKET DATA
# ─────────────────────────────────────────────
def enrich_market(cb: CoinbaseClient) -> dict:
    data = {}
    for pair in CONFIG["pairs"]:
        try:
            prices  = cb.get_best_bid_ask(pair)
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
            chg_str = f"{change_24h:+.2f}%" if change_24h is not None else "n/d"
            log.info(f"{pair}: €{prices['mid']:.4f}  24h={chg_str}")
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
        f"volatilità={d.get('volatility') or 0:.2f}%"
        for pair, d in market_data.items()
        if d.get("change_24h") is not None
    )

    prompt = f"""Profilo di rischio attivo: {_profile_name.upper()}
{CONFIG['ai_style']}

━━━ STATO PORTAFOGLIO ━━━
EUR disponibile : €{eur_balance:.2f}
EUR usabile     : €{usable:.2f}  (riserva €{CONFIG['cash_reserve_eur']:.0f} intoccabile)
Posizioni aperte: {len(portfolio)} / max {CONFIG['max_open_positions']}

CRYPTO IN PORTAFOGLIO:
{portfolio_lines}

PREZZI DI MERCATO (Coinbase, dati reali):
{market_lines}

━━━ PARAMETRI PROFILO {_profile_name.upper()} ━━━
Max per trade       : €{CONFIG['max_trade_eur']:.0f}
Take profit         : +{CONFIG['take_profit_pct']:.0f}%
Stop loss           : -{CONFIG['stop_loss_pct']:.0f}%
Momentum minimo     : {CONFIG['min_momentum_pct']:+.1f}% (24h)
Max posizioni aperte: {CONFIG['max_open_positions']}

━━━ REGOLE FISSE ━━━
- Non superare €{CONFIG['max_trade_eur']:.0f} per singolo trade
- Non usare la riserva EUR di €{CONFIG['cash_reserve_eur']:.0f}
- Non aprire più di {CONFIG['max_open_positions']} posizioni
- Solo coppie autorizzate: {CONFIG['pairs']}

Analizza e decidi 0-2 operazioni massimo.
RISPOSTA: SOLO JSON array valido, niente testo extra:
[{{"action":"buy","pair":"BTC-EUR","amount_eur":20,"reason":"motivazione breve"}}]
Se non operi: []"""

    msg = client.messages.create(
        model      = "claude-sonnet-4-20250514",
        max_tokens = 400,
        messages   = [{"role": "user", "content": prompt}],
    )
    raw = msg.content[0].text.strip()
    log.info(f"AI [{_profile_name}] → {raw}")
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        m = re.search(r'\[[\s\S]*?\]', raw)
        return json.loads(m.group(0)) if m else []


# ─────────────────────────────────────────────
# CRASH GUARD
# ─────────────────────────────────────────────
def crash_detected(market_data: dict) -> bool:
    for pair, d in market_data.items():
        if d.get("change_24h") is not None and d["change_24h"] < -CONFIG["crash_threshold_pct"]:
            log.warning(f"⚠️  {pair} in crollo ({d['change_24h']:.1f}%) — nessuna operazione")
            return True
    return False


# ─────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────
def main():
    mode = "🟡 DRY-RUN" if CONFIG["dry_run"] else "🔴 LIVE"
    log.info("═" * 60)
    log.info(f"AI TRADER [{mode}] — Profilo: {_profile_name.upper()}")
    log.info(f"Coppie: {CONFIG['pairs']}")
    log.info(f"Max trade: €{CONFIG['max_trade_eur']}  |  Riserva: €{CONFIG['cash_reserve_eur']}")
    log.info(f"Take profit: +{CONFIG['take_profit_pct']}%  |  Stop loss: -{CONFIG['stop_loss_pct']}%")
    log.info(f"Orario: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

    cb_key    = os.getenv("COINBASE_API_KEY",    "")
    cb_secret = os.getenv("COINBASE_API_SECRET", "")
    ai_key    = os.getenv("ANTHROPIC_API_KEY",   "")
    if not all([cb_key, cb_secret, ai_key]):
        log.error("Credenziali mancanti — controlla i Secrets GitHub")
        sys.exit(1)

    cb     = CoinbaseClient(cb_key, cb_secret)
    claude = anthropic.Anthropic(api_key=ai_key)

    try:
        eur_balance = cb.get_balance("EUR")
        log.info(f"✓ Coinbase OK — EUR disponibile: €{eur_balance:.2f}")
    except Exception as e:
        log.error(f"✗ Connessione Coinbase fallita: {e}")
        sys.exit(1)

    market_data = enrich_market(cb)
    if not market_data:
        log.warning("Nessun dato di mercato — ciclo saltato")
        sys.exit(0)

    if crash_detected(market_data):
        sys.exit(0)

    portfolio = cb.get_portfolio()
    log.info(f"Posizioni aperte: {list(portfolio.keys()) or 'nessuna'}")

    trades = ask_ai(claude, market_data, portfolio, eur_balance)
    log.info(f"AI suggerisce {len(trades)} operazioni")

    for t in trades:
        action     = t.get("action")
        pair       = t.get("pair")
        amount_eur = float(t.get("amount_eur", 0))
        reason     = t.get("reason", "")

        if pair not in CONFIG["pairs"]:
            log.warning(f"Coppia non autorizzata: {pair} — skip"); continue
        if amount_eur > CONFIG["max_trade_eur"]:
            amount_eur = CONFIG["max_trade_eur"]
            log.warning(f"Importo ridotto al massimo: €{amount_eur}")
        usable = eur_balance - CONFIG["cash_reserve_eur"]
        if action == "buy" and amount_eur > usable:
            log.warning(f"Fondi insufficienti (usabili €{usable:.2f}) — skip"); continue
        if action == "buy" and len(portfolio) >= CONFIG["max_open_positions"]:
            log.warning(f"Max posizioni raggiunto ({CONFIG['max_open_positions']}) — skip"); continue

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
