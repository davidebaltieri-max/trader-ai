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

    # ── BILANCIATO ────────────────────────────────────────────
    # Solo large cap affidabili. Movimenti lenti, drawdown limitati.
    # Simile a un ETF obbligazionario misto crypto.
    "bilanciato": {
        "pairs": [
            "BTC-EUR",   # Bitcoin      — riserva di valore, dominanza di mercato
            "ETH-EUR",   # Ethereum     — smart contract, ecosistema DeFi
        ],
        "max_trade_eur":       15.0,
        "cash_reserve_eur":    80.0,
        "crash_threshold_pct": 8.0,
        "take_profit_pct":     12.0,
        "stop_loss_pct":       6.0,
        "max_open_positions":  2,
        "ai_style": (
            "Sei MOLTO conservativo. Priorità assoluta: preservare il capitale. "
            "Opera solo su BTC ed ETH con segnali forti e chiari. "
            "Preferisci non operare se il mercato è incerto o laterale."
        ),
    },

    # ── MEDIO ─────────────────────────────────────────────────
    # Large cap + mid cap selezionate. Buona diversificazione,
    # simile a un ETF crypto diversificato.
    "medio": {
        "pairs": [
            "BTC-EUR",   # Bitcoin      — ancora del portafoglio
            "ETH-EUR",   # Ethereum     — layer 1 principale
            "SOL-EUR",   # Solana       — layer 1 ad alte performance
            "ADA-EUR",   # Cardano      — layer 1 accademico, bassa volatilità relativa
            "DOT-EUR",   # Polkadot     — interoperabilità blockchain
            "LINK-EUR",  # Chainlink    — oracoli dati, infrastruttura DeFi
        ],
        "max_trade_eur":       30.0,
        "cash_reserve_eur":    50.0,
        "crash_threshold_pct": 15.0,
        "take_profit_pct":     20.0,
        "stop_loss_pct":       10.0,
        "max_open_positions":  5,
        "ai_style": (
            "Sei bilanciato. Diversifichi tra large cap (BTC, ETH) e mid cap selezionate "
            "(SOL, ADA, DOT, LINK). Preferisci asset con fondamentali solidi e momentum "
            "positivo. Mantieni sempre BTC o ETH come posizione principale."
        ),
    },

    # ── PERFORMANTE ───────────────────────────────────────────
    # Ampia diversificazione su tutto lo spettro crypto.
    # Alto potenziale, alta volatilità. Simile a un ETF crypto small/mid cap.
    "performante": {
        "pairs": [
            "BTC-EUR",    # Bitcoin       — base del portafoglio
            "ETH-EUR",    # Ethereum      — layer 1 principale
            "SOL-EUR",    # Solana        — alta velocità, ecosistema NFT/DeFi
            "ADA-EUR",    # Cardano       — layer 1 stabile
            "DOT-EUR",    # Polkadot      — parachain, interoperabilità
            "LINK-EUR",   # Chainlink     — oracoli, infrastruttura Web3
            "AVAX-EUR",   # Avalanche     — layer 1 ad alta scalabilità
            "MATIC-EUR",  # Polygon       — layer 2 Ethereum, commissioni basse
            "UNI-EUR",    # Uniswap       — DEX leader, token di governance DeFi
            "ATOM-EUR",   # Cosmos        — hub interchain, IBC protocol
        ],
        "max_trade_eur":       50.0,
        "cash_reserve_eur":    30.0,
        "crash_threshold_pct": 25.0,
        "take_profit_pct":     35.0,
        "stop_loss_pct":       15.0,
        "max_open_positions":  7,
        "ai_style": (
            "Sei aggressivo e orientato alla performance massima. Diversifichi su tutto lo "
            "spettro: large cap (BTC/ETH), layer 1 alternativi (SOL/ADA/AVAX), "
            "infrastruttura DeFi (LINK/UNI), layer 2 (MATIC) e interoperabilità (DOT/ATOM). "
            "Puoi fare dip-buying su cali moderati. Ruota tra settori in base al momentum. "
            "Priorità: massimizzare i ritorni accettando volatilità elevata."
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
def pct_change(closes: list, bars: int) -> float | None:
    """Variazione percentuale sulle ultime `bars` candele."""
    if len(closes) < bars + 1:
        return None
    return ((closes[0] - closes[bars]) / closes[bars]) * 100


def enrich_market(cb: CoinbaseClient) -> dict:
    """
    Raccoglie dati multi-timeframe per ogni coppia:
      - 1h  (ultime 2 candele da 30min)
      - 4h  (ultime 8 candele da 30min)
      - 24h (ultime 48 candele da 30min)
    Usa candele da 30 minuti per massima granularità.
    """
    data = {}
    for pair in CONFIG["pairs"]:
        try:
            prices = cb.get_best_bid_ask(pair)
            if not prices.get("mid"):
                continue

            # 50 candele da 30min = ~25 ore di storia
            candles = cb.get_candles(pair, granularity="THIRTY_MINUTE", limit=50)
            closes  = [float(c["close"]) for c in candles if "close" in c]
            volumes = [float(c.get("volume", 0)) for c in candles if "close" in c]

            change_1h  = pct_change(closes, 2)   # 2 x 30min = 1h
            change_4h  = pct_change(closes, 8)   # 8 x 30min = 4h
            change_24h = pct_change(closes, 48)  # 48 x 30min = 24h

            # Volatilità: deviazione standard delle variazioni % a 30min (ultime 12 = 6h)
            volatility = None
            if len(closes) >= 13:
                changes    = [(closes[i] - closes[i+1]) / closes[i+1] * 100
                              for i in range(12)]
                volatility = statistics.stdev(changes)

            # Volume medio ultime 4 candele vs precedenti 4 (trend volume)
            vol_recent = sum(volumes[:4]) / 4 if len(volumes) >= 4 else None
            vol_prev   = sum(volumes[4:8]) / 4 if len(volumes) >= 8 else None
            vol_ratio  = (vol_recent / vol_prev) if (vol_recent and vol_prev and vol_prev > 0) else None

            data[pair] = {
                **prices,
                "change_1h":  change_1h,
                "change_4h":  change_4h,
                "change_24h": change_24h,
                "volatility": volatility,
                "vol_ratio":  vol_ratio,   # >1 = volume in aumento
            }

            log.info(
                f"{pair}: €{prices['mid']:.4f} | "
                f"1h={change_1h:+.2f}% " if change_1h is not None else
                f"{pair}: €{prices['mid']:.4f} | 1h=n/d "
                f"4h={change_4h:+.2f}% " if change_4h is not None else "4h=n/d "
                f"24h={change_24h:+.2f}%" if change_24h is not None else "24h=n/d"
            )

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

    def fmt(v, suffix="%"):
        return f"{v:+.2f}{suffix}" if v is not None else "n/d"

    market_lines = "\n".join(
        f"  {pair}: €{d['mid']:.4f} | "
        f"1h={fmt(d.get('change_1h'))} "
        f"4h={fmt(d.get('change_4h'))} "
        f"24h={fmt(d.get('change_24h'))} | "
        f"vol×={fmt(d.get('vol_ratio'), suffix='x') if d.get('vol_ratio') else 'n/d'} "
        f"volat={fmt(d.get('volatility'))}"
        for pair, d in market_data.items()
    )

    prompt = f"""Profilo: {_profile_name.upper()} — {CONFIG['ai_style']}

PORTAFOGLIO:
  EUR disponibile: €{eur_balance:.2f} (usabile: €{usable:.2f}, riserva €{CONFIG['cash_reserve_eur']:.0f})
  Posizioni: {len(portfolio)}/{CONFIG['max_open_positions']}

CRYPTO IN PORTAFOGLIO:
{portfolio_lines}

MERCATO — dati multi-timeframe (Coinbase live, candele 30min):
{market_lines}

Legenda colonne: 1h=ultima ora | 4h=ultime 4 ore | 24h=ultime 24 ore
vol×=rapporto volume recente/precedente (>1.2 = volume in aumento)
volat=volatilità % a 6 ore (bassa <0.5, media 0.5-1.5, alta >1.5)

INTERPRETAZIONE SUGGERITA:
- Momentum rialzista confermato: 1h>0% E 4h>0% E 24h>0%
- Rimbalzo (possibile buy): 24h<0% ma 1h>0% e 4h>0% con vol× in aumento
- Momentum ribassista: 1h<0% E 4h<0% → evita acquisti
- Breakout: vol×>1.5 con variazione positiva su 1h e 4h

LIMITI:
- Max €{CONFIG['max_trade_eur']:.0f} per trade
- Take profit: +{CONFIG['take_profit_pct']:.0f}% | Stop loss: -{CONFIG['stop_loss_pct']:.0f}%
- Solo coppie: {CONFIG['pairs']}
- Non superare {CONFIG['max_open_positions']} posizioni aperte

REGOLA CRITICA SULLE POSIZIONI:
{"⛔ Portafoglio PIENO (" + str(len(portfolio)) + "/" + str(CONFIG["max_open_positions"]) + " slot). NON proporre acquisti. Proponi SOLO vendite se qualche posizione ha raggiunto take profit/stop loss, altrimenti restituisci []." if len(portfolio) >= CONFIG["max_open_positions"] else "✅ Hai " + str(CONFIG["max_open_positions"] - len(portfolio)) + " slot liberi. Puoi proporre acquisti e/o vendite."}

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

    # Crash guard — controlla su 1h e 4h oltre che 24h
    for pair, d in market_data.items():
        c24 = d.get("change_24h") or 0
        c4  = d.get("change_4h")  or 0
        c1  = d.get("change_1h")  or 0
        threshold = CONFIG["crash_threshold_pct"]
        # Segnale di crash: 24h sotto soglia, OPPURE crollo rapido nelle ultime 4h
        if c24 < -threshold or c4 < -(threshold * 0.5) or c1 < -(threshold * 0.25):
            log.warning(
                f"⚠️  {pair}: 1h={c1:+.2f}% 4h={c4:+.2f}% 24h={c24:+.2f}% "
                f"— segnale di crollo, operazioni sospese"
            )
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
